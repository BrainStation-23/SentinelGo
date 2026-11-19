package packages

import (
	"context"
	"path/filepath"
	"testing"
)

func runProjectScan(t *testing.T, home string) map[string]Package {
	t.Helper()
	pinHomes(t, home)
	pkgs, complete, more := newProjectScanner().run(context.Background(), Settings{ProjectScan: true, MaxDepth: 6})
	if !complete || more {
		t.Fatalf("complete=%v more=%v, want a finished pass", complete, more)
	}
	return names(pkgs)
}

func TestProjectScan_Venv(t *testing.T) {
	home := filepath.Join(t.TempDir(), "gina")
	site := func(venv string) string {
		return filepath.Join(venv, "lib", "python3.12", "site-packages", "requests-2.31.0.dist-info", "METADATA")
	}

	// Only an unpinned requirements.txt: the venv is the record.
	unpinned := filepath.Join(home, "unpinned")
	write(t, filepath.Join(unpinned, "requirements.txt"), "requests>=2\n")
	write(t, filepath.Join(unpinned, ".venv", "pyvenv.cfg"), "home = /usr/bin\n")
	write(t, site(filepath.Join(unpinned, ".venv")), "Name: requests\nVersion: 2.31.0\n")
	write(t, filepath.Join(unpinned, ".venv", "lib", "python3.12", "site-packages", "nested", "package-lock.json"), lockV3)

	// A lockfile: it is reported, the venv isn't.
	locked := filepath.Join(home, "locked")
	write(t, filepath.Join(locked, "poetry.lock"), string(fixture(t, "poetry.lock")))
	write(t, filepath.Join(locked, "venv", "pyvenv.cfg"), "")
	write(t, site(filepath.Join(locked, "venv")), "Name: requests\nVersion: 2.31.0\n")

	// A folder named env without pyvenv.cfg is not a virtualenv.
	notVenv := filepath.Join(home, "notvenv")
	write(t, site(filepath.Join(notVenv, "env")), "Name: requests\nVersion: 2.31.0\n")

	got := runProjectScan(t, home)
	venv := filepath.Join(unpinned, ".venv")
	p, ok := got["requests@2.31.0 "+venv]
	if !ok || p.Scope != ScopeProject || p.Ecosystem != EcosystemPyPI || p.User != "gina" {
		t.Errorf("venv package = %+v, %v; got %v", p, ok, got)
	}
	for k := range got {
		switch {
		case k == "requests@2.31.0 "+filepath.Join(locked, "venv"):
			t.Errorf("reported the venv of a locked project: %s", k)
		case k == "requests@2.31.0 "+filepath.Join(notVenv, "env"):
			t.Errorf("reported a folder without pyvenv.cfg: %s", k)
		case k == "keyv@4.5.4 "+filepath.Join(venv, "lib", "python3.12", "site-packages", "nested", "package-lock.json"):
			t.Errorf("walked into the venv: %s", k)
		}
	}
	if _, ok := got["requests@2.31.0 "+filepath.Join(locked, "poetry.lock")]; !ok {
		t.Errorf("poetry.lock not reported: %v", got)
	}
}

func TestProjectScan_Ecosystems(t *testing.T) {
	home := filepath.Join(t.TempDir(), "hank")

	goApp := filepath.Join(home, "goapp")
	write(t, filepath.Join(goApp, "go.mod"), string(fixture(t, "go.mod")))
	write(t, filepath.Join(goApp, "go.sum"), string(fixture(t, "go.sum")))

	dotnet := filepath.Join(home, "dotnet")
	write(t, filepath.Join(dotnet, "App.csproj"), "<Project/>")
	write(t, filepath.Join(dotnet, "obj", "project.assets.json"), string(fixture(t, "project.assets.json")))
	write(t, filepath.Join(dotnet, "obj", "Debug", "packages.lock.json"), string(fixture(t, "packages.lock.json"))) // not walked
	write(t, filepath.Join(dotnet, "bin", "Debug", "packages.lock.json"), string(fixture(t, "packages.lock.json")))
	write(t, filepath.Join(home, "notes", "project.assets.json"), string(fixture(t, "project.assets.json"))) // not in obj

	rust := filepath.Join(home, "rust")
	write(t, filepath.Join(rust, "Cargo.toml"), "[package]\n")
	write(t, filepath.Join(rust, "Cargo.lock"), string(fixture(t, "Cargo.lock")))
	write(t, filepath.Join(rust, "target", "x", "Cargo.lock"), string(fixture(t, "Cargo.lock")))
	write(t, filepath.Join(home, "target", "Cargo.lock"), string(fixture(t, "Cargo.lock"))) // no Cargo.toml beside: walked

	write(t, filepath.Join(home, "bunapp", "bun.lockb"), "\x00binary")
	write(t, filepath.Join(home, "rapp", "renv.lock"), string(fixture(t, "renv.lock")))
	write(t, filepath.Join(home, "rapp", "renv", "library", "x", "renv.lock"), string(fixture(t, "renv.lock")))

	got := runProjectScan(t, home)
	for _, k := range []string{
		"github.com/BurntSushi/toml@v1.3.2 " + filepath.Join(goApp, "go.mod"),
		"golang.org/x/text@v0.13.0 " + filepath.Join(goApp, "go.sum"),
		"Newtonsoft.Json@13.0.1 " + filepath.Join(dotnet, "obj", "project.assets.json"),
		"serde@1.0.197 " + filepath.Join(rust, "Cargo.lock"),
		"serde@1.0.197 " + filepath.Join(home, "target", "Cargo.lock"),
		"jsonlite@1.8.8 " + filepath.Join(home, "rapp", "renv.lock"),
	} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing %q", k)
		}
	}
	for _, k := range []string{
		"golang.org/x/text@v0.13.0 " + filepath.Join(goApp, "go.mod"),
		"github.com/BurntSushi/toml@v1.3.2 " + filepath.Join(goApp, "go.sum"), // de-duplicated into go.mod
		"Serilog@3.1.1 " + filepath.Join(dotnet, "obj", "Debug", "packages.lock.json"),
		"Serilog@3.1.1 " + filepath.Join(dotnet, "bin", "Debug", "packages.lock.json"),
		"Newtonsoft.Json@13.0.1 " + filepath.Join(home, "notes", "project.assets.json"),
		"serde@1.0.197 " + filepath.Join(rust, "target", "x", "Cargo.lock"),
		"jsonlite@1.8.8 " + filepath.Join(home, "rapp", "renv", "library", "x", "renv.lock"),
	} {
		if _, ok := got[k]; ok {
			t.Errorf("unexpected %q", k)
		}
	}
	if t.Failed() {
		t.Logf("got %v", got)
	}
	if p := got["serde@1.0.197 "+filepath.Join(rust, "Cargo.lock")]; p.Ecosystem != EcosystemCargo || p.Scope != ScopeProject {
		t.Errorf("serde = %+v", p)
	}
}

func TestLockfileFor_Ecosystems(t *testing.T) {
	for name, want := range map[string]string{
		"bun.lock": EcosystemNPM, "pdm.lock": EcosystemPyPI, "pylock.toml": EcosystemPyPI, "pylock.dev.toml": EcosystemPyPI,
		"packages.lock.json": EcosystemNuGet, "packages.config": EcosystemNuGet, "project.assets.json": EcosystemNuGet,
		"gradle.lockfile": EcosystemMaven, "buildscript-gradle.lockfile": EcosystemMaven, "pom.xml": EcosystemMaven,
		"Cargo.lock": EcosystemCargo, "Gemfile.lock": EcosystemRubyGems, "gems.locked": EcosystemRubyGems,
		"pubspec.lock": EcosystemPub, "mix.lock": EcosystemHex, "Package.resolved": EcosystemSwift,
		"renv.lock": EcosystemCRAN,
	} {
		if eco, _, ok := lockfileFor(name); !ok || eco != want {
			t.Errorf("lockfileFor(%q) = %q, %v; want %q", name, eco, ok, want)
		}
	}
	for _, name := range []string{"go.mod", "go.sum", "bun.lockb", "pylock..toml", "pylock.toml.bak", "Cargo.toml", "build.gradle"} {
		if _, _, ok := lockfileFor(name); ok {
			t.Errorf("lockfileFor(%q) matched", name)
		}
	}
}
