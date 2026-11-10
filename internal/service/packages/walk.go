package packages

import (
	"context"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"sentinelgo/internal/sanitize"
)

// Budget of one project-scan run. A pass that doesn't fit continues in the
// next run where it stopped, so a large home costs a few short runs instead
// of one long one.
const (
	projectRunTimeout = 3 * time.Minute
	projectRunEntries = 250_000
	// maxLockfileBytes caps one lockfile. Large monorepo lockfiles reach a
	// few MB.
	maxLockfileBytes = 16 << 20
	// maxProjectPackages caps the packages one pass keeps.
	maxProjectPackages = 1_000_000
	// defaultMaxDepth is the walk depth when the server sends none.
	defaultMaxDepth = 6
)

// lockfile parsers by file name.
var lockfiles = map[string]struct {
	ecosystem string
	parse     func([]byte) []nameVersion
}{
	"package-lock.json":   {EcosystemNPM, parsePackageLock},
	"npm-shrinkwrap.json": {EcosystemNPM, parsePackageLock},
	"yarn.lock":           {EcosystemNPM, parseYarnLock},
	"pnpm-lock.yaml":      {EcosystemNPM, parsePnpmLock},
	"poetry.lock":         {EcosystemPyPI, parseTOMLPackages},
	"uv.lock":             {EcosystemPyPI, parseTOMLPackages},
	"Pipfile.lock":        {EcosystemPyPI, parsePipfileLock},
	"composer.lock":       {EcosystemPackagist, parseComposerLock},
}

// lockfileFor returns the parser for a file name; requirements*.txt counts.
func lockfileFor(name string) (ecosystem string, parse func([]byte) []nameVersion, ok bool) {
	if l, found := lockfiles[name]; found {
		return l.ecosystem, l.parse, true
	}
	if strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt") {
		return EcosystemPyPI, parseRequirements, true
	}
	return "", nil, false
}

// skipDirs are never walked into: dependency trees (their packages come
// from the lockfile), virtual environments and build output. Directories
// whose name starts with "." are skipped too (.git, caches, tool homes).
var skipDirs = map[string]bool{
	"node_modules": true, "vendor": true, "venv": true, "env": true,
	"__pycache__": true, "site-packages": true, "dist-packages": true,
	"bower_components": true, "jspm_packages": true,
}

type projectRoot struct {
	path   string
	user   string
	dev    uint64
	hasDev bool
}

type walkItem struct {
	dir   string
	depth int
	root  int
}

// projectScanner walks the project roots for lockfiles, in passes that may
// span several runs.
type projectScanner struct {
	mu      sync.Mutex
	key     string // settings the pass was started with
	roots   []projectRoot
	queue   []walkItem
	current []Package // found in the pass so far
	last    []Package // the last finished pass
	hasLast bool
	errors  int
}

func newProjectScanner() *projectScanner { return &projectScanner{} }

// reset forgets every pass (project scanning was turned off).
func (p *projectScanner) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clear("")
}

// clear drops all pass state; key is the settings the next pass is for.
// The caller holds mu.
func (p *projectScanner) clear(key string) {
	p.key, p.roots, p.queue, p.current, p.last, p.hasLast, p.errors = key, nil, nil, nil, nil, false, 0
}

// run continues the current pass within the run budget. It returns the
// project packages to report, whether they form a complete inventory (a
// pass has finished: until the next one does, the last finished pass plus
// what this one found so far), and whether the pass still has work left.
func (p *projectScanner) run(ctx context.Context, s Settings) (pkgs []Package, complete, more bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	depth := s.MaxDepth
	if depth <= 0 {
		depth = defaultMaxDepth
	}
	key := strconv.Itoa(depth) + "\x00" + strings.Join(s.Roots, "\x00")
	if key != p.key {
		// New roots or depth: what earlier passes found no longer answers
		// for this configuration.
		p.clear(key)
	}
	if len(p.queue) == 0 {
		p.startPass(s.Roots)
	}

	ctx, cancel := context.WithTimeout(ctx, projectRunTimeout)
	defer cancel()
	entries := 0
	for len(p.queue) > 0 && entries < projectRunEntries && ctx.Err() == nil && len(p.current) < maxProjectPackages {
		item := p.queue[0]
		p.queue = p.queue[1:]
		entries += p.visit(item, depth)
	}

	if len(p.queue) == 0 {
		if p.errors > 0 {
			log.Printf("[packages] project scan: %d folders or lockfiles could not be read", p.errors)
		}
		p.last, p.hasLast, p.current = p.current, true, nil
		return slices.Clone(p.last), true, false
	}
	if p.hasLast {
		return append(slices.Clone(p.last), p.current...), true, true
	}
	return slices.Clone(p.current), false, true
}

// startPass queues the roots: the configured ones, or each user's home.
func (p *projectScanner) startPass(configured []string) {
	homes := userHomeDirs()
	paths := configured
	if len(paths) == 0 {
		paths = homes
	}
	p.roots, p.queue, p.current, p.errors = nil, nil, nil, 0
	for _, path := range paths {
		path = filepath.Clean(path)
		if !filepath.IsAbs(path) {
			continue
		}
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || !localFS(path) {
			continue // missing, a link, or a network drive: never walked
		}
		dev, hasDev := deviceOf(info)
		p.roots = append(p.roots, projectRoot{path: path, user: ownerHome(path, homes), dev: dev, hasDev: hasDev})
		p.queue = append(p.queue, walkItem{dir: path, depth: 0, root: len(p.roots) - 1})
	}
}

// visit reads one directory: lockfiles in it are parsed, subdirectories
// within depth are queued. It returns the number of entries read.
func (p *projectScanner) visit(item walkItem, maxDepth int) int {
	entries, err := os.ReadDir(item.dir)
	if err != nil {
		p.errors++ // unreadable (permissions, TCC): its lockfiles were never reported either
		return 1
	}
	root := p.roots[item.root]
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			if item.depth >= maxDepth || !isDir(e) || strings.HasPrefix(name, ".") || skipDirs[name] || skipPlatformDir(name) {
				continue
			}
			info, err := e.Info()
			if err != nil || placeholder(info) {
				continue
			}
			if dev, ok := deviceOf(info); ok && root.hasDev && dev != root.dev {
				continue // another file system mounted inside the root
			}
			p.queue = append(p.queue, walkItem{dir: filepath.Join(item.dir, name), depth: item.depth + 1, root: item.root})
			continue
		}
		if !e.Type().IsRegular() {
			continue
		}
		ecosystem, parse, ok := lockfileFor(name)
		if !ok {
			continue
		}
		p.parseLockfile(filepath.Join(item.dir, name), e, ecosystem, parse, root.user)
	}
	return len(entries)
}

func (p *projectScanner) parseLockfile(path string, e fs.DirEntry, ecosystem string, parse func([]byte) []nameVersion, user string) {
	info, err := e.Info()
	if err != nil || placeholder(info) {
		return // a cloud file not on this device: reading it would download it
	}
	if info.Size() > maxLockfileBytes {
		p.errors++
		log.Printf("[packages] lockfile over %d MB skipped: %s", maxLockfileBytes>>20, sanitize.ForLog(path))
		return
	}
	data, err := readLimited(path, maxLockfileBytes)
	if err != nil {
		p.errors++
		return
	}
	for _, nv := range parse(data) {
		p.current = append(p.current, Package{Ecosystem: ecosystem, Name: nv.name, Version: nv.version,
			Scope: ScopeProject, Location: path, User: user})
	}
}

// ownerHome returns the user whose home holds path, or "" when none does.
func ownerHome(path string, homes []string) string {
	best := ""
	for _, h := range homes {
		h = filepath.Clean(h)
		if (pathHasPrefix(path, h)) && len(h) > len(best) {
			best = h
		}
	}
	if best == "" {
		return ""
	}
	return filepath.Base(best)
}

// pathHasPrefix reports whether path is dir or inside it.
func pathHasPrefix(path, dir string) bool {
	if sameFold(path, dir) {
		return true
	}
	sep := string(filepath.Separator)
	return len(path) > len(dir) && sameFold(path[:len(dir)], dir) && (strings.HasSuffix(dir, sep) || path[len(dir):len(dir)+1] == sep)
}
