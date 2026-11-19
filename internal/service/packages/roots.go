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
	kindPnpmGlobal   = "pnpm-global"   // a pnpm global node_modules (links into its own store)
	kindSitePackages = "site-packages" // a Python site-packages / dist-packages directory
	kindComposerHome = "composer"      // a Composer home (holds vendor/composer/installed.json)
	kindNuGetTools   = "nuget-tools"   // the .NET global tools store (.dotnet/tools/.store)
	kindNuGetCache   = "nuget-cache"   // the NuGet global packages folder (.nuget/packages)
	kindMavenRepo    = "maven-repo"    // a Maven local repository (.m2/repository)
	kindM2Settings   = "m2-settings"   // a Maven settings.xml naming another localRepository
	kindGradleCache  = "gradle-cache"  // Gradle's module cache (caches/modules-2/files-2.1)
	kindGoBin        = "go-bin"        // a folder of go install binaries
	kindGoModCache   = "go-mod-cache"  // the Go module download cache (pkg/mod/cache/download)
	kindCargoHome    = "cargo-home"    // a Cargo home (.crates2.json / .crates.toml: cargo install)
	kindCargoCache   = "cargo-cache"   // a Cargo registry cache (registry/cache/<index>)
	kindGemDir       = "gem-dir"       // a RubyGems GEM_HOME (holds specifications/)
	kindPubGlobal    = "pub-global"    // a dart pub global activate package (holds pubspec.lock)
	kindPubCache     = "pub-cache"     // the Pub hosted cache (hosted/pub.dev)
	kindRLibrary     = "r-library"     // an R library (<pkg>/DESCRIPTION)
)

// rootEcosystem is the ecosystem each root kind reports. A root whose
// ecosystem the server doesn't accept isn't read at all.
var rootEcosystem = map[string]string{
	kindNodeModules: EcosystemNPM, kindPnpmGlobal: EcosystemNPM,
	kindSitePackages: EcosystemPyPI, kindComposerHome: EcosystemPackagist,
	kindNuGetTools: EcosystemNuGet, kindNuGetCache: EcosystemNuGet,
	kindMavenRepo: EcosystemMaven, kindM2Settings: EcosystemMaven, kindGradleCache: EcosystemMaven,
	kindGoBin: EcosystemGo, kindGoModCache: EcosystemGo,
	kindCargoHome: EcosystemCargo, kindCargoCache: EcosystemCargo,
	kindGemDir:    EcosystemRubyGems,
	kindPubGlobal: EcosystemPub, kindPubCache: EcosystemPub,
	kindRLibrary: EcosystemCRAN,
}

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

// CollectGlobal returns the packages installed globally (and, for the
// ecosystems that have one, in the download cache) for the whole machine and
// for every user, and whether every location that exists was read in full.
// accepts says which ecosystems to read; nil reads every one.
func CollectGlobal(ctx context.Context, accepts func(ecosystem string) bool) (pkgs []Package, complete bool) {
	ctx, cancel := context.WithTimeout(ctx, globalTimeout)
	defer cancel()
	s := newScan(ctx)
	wanted := func(kind string) bool { return accepts == nil || accepts(rootEcosystem[kind]) }
	for _, r := range systemRootsFn() {
		if wanted(r.kind) {
			s.collectRoot(r, "")
		}
	}
	for _, home := range userHomeDirs() {
		user := filepath.Base(home)
		for _, hr := range homeRootsFn() {
			if wanted(hr.kind) {
				s.collectRoot(root{kind: hr.kind, pattern: filepath.Join(home, hr.rel)}, user)
			}
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
		case kindPnpmGlobal:
			s.collectPnpmGlobal(dir, user)
		case kindSitePackages:
			s.collectSitePackages(dir, user)
		case kindComposerHome:
			s.collectComposerHome(dir, user)
		case kindNuGetTools:
			s.collectNuGetTools(dir, user)
		case kindNuGetCache:
			s.collectNuGetCache(dir, user)
		case kindMavenRepo:
			s.collectMavenRepo(dir, user)
		case kindM2Settings:
			s.collectM2Settings(dir, user)
		case kindGradleCache:
			s.collectGradleCache(dir, user)
		case kindGoBin:
			s.collectGoBin(dir, user)
		case kindGoModCache:
			s.collectGoModCache(dir, user)
		case kindCargoHome:
			s.collectCargoHome(dir, user)
		case kindCargoCache:
			s.collectCargoCache(dir, user)
		case kindGemDir:
			s.collectGemDir(dir, user)
		case kindPubGlobal:
			s.collectPubGlobal(dir, user)
		case kindPubCache:
			s.collectPubCache(dir, user)
		case kindRLibrary:
			s.collectRLibrary(dir, user)
		}
	}
}
