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
	"package-lock.json":           {EcosystemNPM, parsePackageLock},
	"npm-shrinkwrap.json":         {EcosystemNPM, parsePackageLock},
	"yarn.lock":                   {EcosystemNPM, parseYarnLock},
	"pnpm-lock.yaml":              {EcosystemNPM, parsePnpmLock},
	"bun.lock":                    {EcosystemNPM, parseBunLock},
	"poetry.lock":                 {EcosystemPyPI, parseTOMLPackages},
	"uv.lock":                     {EcosystemPyPI, parseTOMLPackages},
	"Pipfile.lock":                {EcosystemPyPI, parsePipfileLock},
	"pdm.lock":                    {EcosystemPyPI, parsePdmLock},
	"composer.lock":               {EcosystemPackagist, parseComposerLock},
	"project.assets.json":         {EcosystemNuGet, parseProjectAssets}, // only inside obj (see visit)
	"packages.lock.json":          {EcosystemNuGet, parseNuGetLock},
	"packages.config":             {EcosystemNuGet, parsePackagesConfig},
	"gradle.lockfile":             {EcosystemMaven, parseGradleLockfile},
	"buildscript-gradle.lockfile": {EcosystemMaven, parseGradleLockfile},
	"pom.xml":                     {EcosystemMaven, parsePom},
	"Cargo.lock":                  {EcosystemCargo, parseCargoLock},
	"Gemfile.lock":                {EcosystemRubyGems, parseGemfileLock},
	"gems.locked":                 {EcosystemRubyGems, parseGemfileLock},
	"pubspec.lock":                {EcosystemPub, parsePubspecLock},
	"mix.lock":                    {EcosystemHex, parseMixLock},
	"Package.resolved":            {EcosystemSwift, parsePackageResolved},
	"renv.lock":                   {EcosystemCRAN, parseRenvLock},
}

// lockfileFor returns the parser for a file name; requirements*.txt and
// pylock.toml / pylock.<name>.toml count. go.mod is read with its go.sum
// (see visitGoModule), and project.assets.json only inside obj.
func lockfileFor(name string) (ecosystem string, parse func([]byte) []nameVersion, ok bool) {
	if l, found := lockfiles[name]; found {
		return l.ecosystem, l.parse, true
	}
	if strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt") {
		return EcosystemPyPI, parseRequirements, true
	}
	if isPylock(name) {
		return EcosystemPyPI, parsePylock, true
	}
	return "", nil, false
}

// isPylock reports whether name is a PEP 751 lockfile: pylock.toml or
// pylock.<name>.toml.
func isPylock(name string) bool {
	return name == "pylock.toml" || (strings.HasPrefix(name, "pylock.") && strings.HasSuffix(name, ".toml") && len(name) > len("pylock..toml"))
}

// pythonLockfiles are lockfiles that pin a Python project's packages. A
// requirements*.txt counts only when every requirement in it is pinned.
var pythonLockfiles = map[string]bool{
	"poetry.lock": true, "uv.lock": true, "Pipfile.lock": true, "pdm.lock": true,
}

// skipDirs are never walked into: dependency trees (their packages come
// from the lockfile), virtual environments and build output. Directories
// whose name starts with "." are skipped too (.git, caches, tool homes).
var skipDirs = map[string]bool{
	"node_modules": true, "vendor": true, "venv": true, "env": true,
	"__pycache__": true, "site-packages": true, "dist-packages": true,
	"bower_components": true, "jspm_packages": true,
}

// skipBeside are build output and dependency folders, skipped only when the
// project file that makes them one sits beside them: an unrelated folder
// named "build" or "packages" is still walked.
var skipBeside = map[string]func(files map[string]bool) bool{
	"bin":      dotnetProject,
	"packages": dotnetProject, // packages.config restores here
	"target":   anyOf("pom.xml", "Cargo.toml"),
	"build":    anyOf("build.gradle", "build.gradle.kts", "pubspec.yaml"),
	"deps":     anyOf("mix.exs"),
	"_build":   anyOf("mix.exs"),
	"Pods":     anyOf("Podfile"),
}

func anyOf(names ...string) func(map[string]bool) bool {
	return func(files map[string]bool) bool {
		for _, n := range names {
			if files[n] {
				return true
			}
		}
		return false
	}
}

// dotnetProject reports whether a folder holds a .NET project or solution.
func dotnetProject(files map[string]bool) bool {
	for name := range files {
		switch strings.ToLower(filepath.Ext(name)) {
		case ".csproj", ".fsproj", ".vbproj", ".sln", ".slnx":
			return true
		}
	}
	return false
}

// venvDirs are the virtualenv folder names checked in a Python project
// without a lockfile (#543).
var venvDirs = []string{".venv", "venv", "env"}

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
	// binaryLocks counts bun.lockb files: Bun's old binary lockfile can't be
	// read without running Bun.
	binaryLocks int
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
	p.key, p.roots, p.queue, p.current, p.last, p.hasLast, p.errors, p.binaryLocks = key, nil, nil, nil, nil, false, 0, 0
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
		if p.binaryLocks > 0 {
			log.Printf("[packages] project scan: skipped %d bun.lockb files (binary; re-save as bun.lock to report them)", p.binaryLocks)
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
	p.roots, p.queue, p.current, p.errors, p.binaryLocks = nil, nil, nil, 0, 0
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
	files := make(map[string]bool)
	for _, e := range entries {
		if e.Type().IsRegular() {
			files[e.Name()] = true
		}
	}
	read := len(entries)
	pyLocked := false
	var venvs []fs.DirEntry
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			if !isDir(e) {
				continue // a link or junction: never followed
			}
			if slices.Contains(venvDirs, name) {
				venvs = append(venvs, e)
			}
			if name == "obj" && dotnetProject(files) {
				// Only the restore graph matters in obj; its build output
				// isn't walked.
				p.parseLockfileAt(filepath.Join(item.dir, name, "project.assets.json"), EcosystemNuGet, parseProjectAssets, root.user)
				continue
			}
			if item.depth >= maxDepth || strings.HasPrefix(name, ".") || skipDirs[name] || skipPlatformDir(name) {
				continue
			}
			if skip := skipBeside[name]; skip != nil && skip(files) {
				continue
			}
			if name == "library" && filepath.Base(item.dir) == "renv" {
				continue // renv's package library: renv.lock covers it
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
		switch {
		case name == "bun.lockb":
			p.binaryLocks++
			continue
		case name == "go.mod":
			p.visitGoModule(item.dir, e, files["go.sum"], root.user)
			continue
		case name == "project.assets.json" && filepath.Base(item.dir) != "obj":
			continue
		}
		ecosystem, parse, ok := lockfileFor(name)
		if !ok {
			continue
		}
		data := p.parseLockfile(filepath.Join(item.dir, name), e, ecosystem, parse, root.user)
		if pythonLockfiles[name] || isPylock(name) ||
			(ecosystem == EcosystemPyPI && data != nil && requirementsPinned(data)) {
			pyLocked = true
		}
	}
	if !pyLocked {
		for _, v := range venvs {
			read += p.visitVenv(filepath.Join(item.dir, v.Name()), root.user)
		}
	}
	return read
}

// parseLockfile parses one lockfile and returns its content (nil when it
// wasn't read).
func (p *projectScanner) parseLockfile(path string, e fs.DirEntry, ecosystem string, parse func([]byte) []nameVersion, user string) []byte {
	info, err := e.Info()
	if err != nil {
		return nil
	}
	return p.parseLockfileInfo(path, info, ecosystem, parse, user)
}

// parseLockfileAt parses a lockfile that may not exist (a fixed name inside
// a folder that isn't walked).
func (p *projectScanner) parseLockfileAt(path, ecosystem string, parse func([]byte) []nameVersion, user string) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	p.parseLockfileInfo(path, info, ecosystem, parse, user)
}

func (p *projectScanner) parseLockfileInfo(path string, info fs.FileInfo, ecosystem string, parse func([]byte) []nameVersion, user string) []byte {
	data := p.readLockfile(path, info)
	if data == nil {
		return nil
	}
	for _, nv := range parse(data) {
		p.current = append(p.current, Package{Ecosystem: ecosystem, Name: nv.name, Version: nv.version,
			Scope: ScopeProject, Location: path, User: user})
	}
	return data
}

// readLockfile reads a lockfile within the size cap. Cloud placeholders
// are never read: reading one would download it.
func (p *projectScanner) readLockfile(path string, info fs.FileInfo) []byte {
	if placeholder(info) {
		return nil
	}
	if info.Size() > maxLockfileBytes {
		p.errors++
		log.Printf("[packages] lockfile over %d MB skipped: %s", maxLockfileBytes>>20, sanitize.ForLog(path))
		return nil
	}
	data, err := readLimited(path, maxLockfileBytes)
	if err != nil {
		p.errors++
		return nil
	}
	return data
}

// visitGoModule reports a Go module's dependencies: the requirements of
// go.mod (located at go.mod), and the other modules go.sum says were
// downloaded (located at go.sum).
func (p *projectScanner) visitGoModule(dir string, e fs.DirEntry, hasSum bool, user string) {
	modPath := filepath.Join(dir, "go.mod")
	info, err := e.Info()
	if err != nil {
		return
	}
	mod := p.readLockfile(modPath, info)
	if mod == nil {
		return
	}
	var sum []byte
	sumPath := filepath.Join(dir, "go.sum")
	if hasSum {
		if si, err := os.Lstat(sumPath); err == nil && si.Mode().IsRegular() {
			sum = p.readLockfile(sumPath, si)
		}
	}
	direct, rest := parseGoModule(mod, sum)
	for _, nv := range direct {
		p.current = append(p.current, Package{Ecosystem: EcosystemGo, Name: nv.name, Version: nv.version,
			Scope: ScopeProject, Location: modPath, User: user})
	}
	for _, nv := range rest {
		p.current = append(p.current, Package{Ecosystem: EcosystemGo, Name: nv.name, Version: nv.version,
			Scope: ScopeProject, Location: sumPath, User: user})
	}
}

// visitVenv reports the packages installed in a project's virtualenv
// (#543): only a folder with a pyvenv.cfg is one. Its site-packages is read
// as a global install is, and nothing else in it is walked. The location is
// the virtualenv. It returns the entries read.
func (p *projectScanner) visitVenv(venv, user string) int {
	if info, err := os.Lstat(filepath.Join(venv, "pyvenv.cfg")); err != nil || !info.Mode().IsRegular() {
		return 0
	}
	s := newScan(context.Background())
	for _, pattern := range []string{
		filepath.Join(venv, "lib", "python*", "site-packages"), // Unix
		filepath.Join(venv, "Lib", "site-packages"),            // Windows
	} {
		for _, dir := range s.glob(pattern) {
			if info, err := os.Lstat(dir); err == nil && info.IsDir() {
				s.collectSitePackages(dir, user)
			}
		}
	}
	if !s.complete {
		p.errors++
	}
	for _, pkg := range s.pkgs {
		pkg.Scope, pkg.Location = ScopeProject, venv
		p.current = append(p.current, pkg)
	}
	return s.files + s.dirs
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
