package packages

import (
	"context"
	"path/filepath"
	"time"

	"sentinelgo/internal/userhomes"
)

// Root kinds: what a location holds.
const (
	kindNodeModules  = "node_modules"  // a global node_modules directory
	kindSitePackages = "site-packages" // a Python site-packages / dist-packages directory
	kindComposerHome = "composer"      // a Composer home (holds vendor/composer/installed.json)
)

// root is a global install location. pattern may hold * in a path segment
// (a Node or Python version).
type root struct {
	kind    string
	pattern string
}

// homeRoot is a location relative to a user's home directory.
type homeRoot struct {
	kind string
	rel  string
}

// globalTimeout bounds collecting global installs. They live in a few fixed
// folders, so a run normally takes well under a second.
const globalTimeout = 2 * time.Minute

// userHomeDirs lists the users' homes; a var so tests can pin it.
var userHomeDirs = userhomes.Dirs

// platform roots; vars so tests can point them at a temp tree.
var (
	systemRootsFn = systemRoots
	homeRootsFn   = homeRoots
)

// CollectGlobal returns the packages installed globally for the whole
// machine and for every user, and whether every location that exists was
// read in full.
func CollectGlobal(ctx context.Context) (pkgs []Package, complete bool) {
	ctx, cancel := context.WithTimeout(ctx, globalTimeout)
	defer cancel()
	s := newScan(ctx)
	for _, r := range systemRootsFn() {
		s.collectRoot(r, "")
	}
	for _, home := range userHomeDirs() {
		user := filepath.Base(home)
		for _, hr := range homeRootsFn() {
			s.collectRoot(root{kind: hr.kind, pattern: filepath.Join(home, hr.rel)}, user)
		}
	}
	return s.pkgs, s.complete
}

func (s *scan) collectRoot(r root, user string) {
	for _, dir := range s.glob(r.pattern) {
		if s.stopped() {
			return
		}
		switch r.kind {
		case kindNodeModules:
			s.collectNodeModules(dir, user)
		case kindSitePackages:
			s.collectSitePackages(dir, user)
		case kindComposerHome:
			s.collectComposerHome(dir, user)
		}
	}
}
