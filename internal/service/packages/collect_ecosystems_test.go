package packages

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// copyFile copies src to dst (a real binary for the Go build-info reader).
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src) // #nosec G304 -- the test binary
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(dst) // #nosec G304 -- a temp dir
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// symlink creates a link and reports whether the platform allowed it
// (Windows needs developer mode or an elevated token).
func symlink(t *testing.T, target, link string) bool {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Logf("symlinks not available, pnpm links not checked: %v", err)
		return false
	}
	return true
}

func j(parts ...string) string { return filepath.Join(parts...) }

func TestCollectGlobal_Ecosystems(t *testing.T) {
	dir := t.TempDir()
	sys := j(dir, "sys")
	alice := j(dir, "home", "alice")

	// npm: Bun global, pnpm global (links into its own store), asdf.
	write(t, j(alice, ".bun", "install", "global", "node_modules", "cowsay", "package.json"), `{"name":"cowsay","version":"1.6.0"}`)
	pnpm := j(alice, "pnpm", "global", "5", "node_modules")
	write(t, j(pnpm, ".pnpm", "is-odd@3.0.1", "node_modules", "is-odd", "package.json"), `{"name":"is-odd","version":"3.0.1"}`)
	write(t, j(pnpm, ".pnpm", "@scope+pkg@1.0.0", "node_modules", "@scope", "pkg", "package.json"), `{"name":"@scope/pkg","version":"1.0.0"}`)
	write(t, j(dir, "project", "package.json"), `{"name":"outside","version":"0.0.1"}`)
	links := symlink(t, j(pnpm, ".pnpm", "is-odd@3.0.1", "node_modules", "is-odd"), j(pnpm, "is-odd")) &&
		symlink(t, j(pnpm, ".pnpm", "@scope+pkg@1.0.0", "node_modules", "@scope", "pkg"), j(pnpm, "@scope", "pkg")) &&
		symlink(t, j(dir, "project"), j(pnpm, "outside")) // leaves the install: not followed
	write(t, j(alice, ".asdf", "installs", "nodejs", "20.11.0", "lib", "node_modules", "npm", "package.json"), `{"name":"npm","version":"10.2.4"}`)

	// PyPI: a pipx venv and a conda env.
	write(t, j(alice, ".local", "share", "pipx", "venvs", "black", "lib", "python3.12", "site-packages", "black-24.2.0.dist-info", "METADATA"), "Name: black\nVersion: 24.2.0\n")
	write(t, j(alice, "miniconda3", "envs", "ds", "lib", "python3.11", "site-packages", "numpy-1.26.4.dist-info", "METADATA"), "Name: numpy\nVersion: 1.26.4\n")

	// NuGet: a global tool and the package cache.
	write(t, j(alice, ".dotnet", "tools", ".store", "dotnetsay", "2.1.4", "dotnetsay.2.1.4.nupkg"), "")
	write(t, j(alice, ".nuget", "packages", "newtonsoft.json", "13.0.1", "newtonsoft.json.nuspec"), "")

	// Maven: ~/.m2, a settings.xml localRepository elsewhere, and Gradle.
	m2 := j(alice, ".m2", "repository")
	write(t, j(m2, "org", "apache", "logging", "log4j", "log4j-core", "2.14.1", "log4j-core-2.14.1.pom"), "<project/>")
	write(t, j(m2, "org", "apache", "logging", "log4j", "log4j-core", "maven-metadata-central.xml"), "")
	write(t, j(m2, "junit", "junit", "4.13.1", "junit-4.13.1.jar"), "")
	write(t, j(m2, "org", "half", "thing", "1.0", "_remote.repositories"), "") // no .pom or .jar
	other := j(dir, "repo2")
	write(t, j(alice, ".m2", "settings.xml"), "<settings><localRepository>"+other+"</localRepository></settings>")
	write(t, j(other, "com", "example", "lib", "3.0.0", "lib-3.0.0.pom"), "<project/>")
	write(t, j(alice, ".gradle", "caches", "modules-2", "files-2.1", "com.google.guava", "guava", "31.1-jre", "abc123", "guava-31.1-jre.jar"), "")

	// Go: a go install binary (the test binary carries build info), a
	// script next to it, and the module cache.
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	copyFile(t, exe, j(alice, "go", "bin", "tool"))
	write(t, j(alice, "go", "bin", "script.sh"), "#!/bin/sh\n")
	modCache := j(alice, "go", "pkg", "mod", "cache", "download")
	write(t, j(modCache, "github.com", "!burnt!sushi", "toml", "@v", "v1.3.2.zip"), "")
	write(t, j(modCache, "github.com", "!burnt!sushi", "toml", "@v", "v1.3.2.mod"), "")
	write(t, j(modCache, "sumdb", "sum.golang.org", "lookup", "@v", "v0.0.1.zip"), "")

	// crates.io: cargo install and the registry cache.
	write(t, j(alice, ".cargo", ".crates2.json"), string(fixture(t, "crates2.json")))
	write(t, j(alice, ".cargo", "registry", "cache", "index.crates.io-6f17d22bba15001f", "serde-1.0.197.crate"), "")
	write(t, j(alice, ".cargo", "registry", "cache", "my-registry.example.com-abc", "private-1.0.0.crate"), "")
	write(t, j(alice, ".cargo", "registry", "cache", "github.com-0123456789abcdef", "private-2.0.0.crate"), "") // another GitHub-hosted index

	// RubyGems, Pub, CRAN.
	gems := j(alice, ".gem", "ruby", "3.2.0", "specifications")
	write(t, j(gems, "rack-2.2.8.gemspec"), "")
	write(t, j(gems, "default", "json-2.6.3.gemspec"), "")
	write(t, j(alice, ".pub-cache", "global_packages", "dhttpd", "pubspec.lock"), string(fixture(t, "pubspec.lock")))
	write(t, j(alice, ".pub-cache", "hosted", "pub.dev", "path-1.9.0", "pubspec.yaml"), "")
	rlib := j(sys, "R", "library")
	write(t, j(rlib, "jsonlite", "DESCRIPTION"), "Package: jsonlite\nVersion: 1.8.8\nRepository: CRAN\n")
	write(t, j(rlib, "stats", "DESCRIPTION"), "Package: stats\nVersion: 4.3.2\nPriority: base\n")

	origSys, origHome, origHomes := systemRootsFn, homeRootsFn, userHomeDirs
	t.Cleanup(func() { systemRootsFn, homeRootsFn, userHomeDirs = origSys, origHome, origHomes })
	systemRootsFn = func() []root { return []root{{kindRLibrary, rlib}} }
	userHomeDirs = func() []string { return []string{alice} }
	homeRootsFn = func() []homeRoot {
		return []homeRoot{
			{kindNodeModules, j(".bun", "install", "global", "node_modules")},
			{kindPnpmGlobal, j("pnpm", "global", "*", "node_modules")},
			{kindNodeModules, j(".asdf", "installs", "nodejs", "*", "lib", "node_modules")},
			{kindSitePackages, j(".local", "share", "pipx", "venvs", "*", "lib", "python*", "site-packages")},
			{kindSitePackages, j("miniconda3", "envs", "*", "lib", "python*", "site-packages")},
			{kindNuGetTools, j(".dotnet", "tools", ".store")},
			{kindNuGetCache, j(".nuget", "packages")},
			{kindMavenRepo, j(".m2", "repository")},
			{kindM2Settings, j(".m2", "settings.xml")},
			{kindGradleCache, j(".gradle", "caches", "modules-2", "files-2.1")},
			{kindGoBin, j("go", "bin")},
			{kindGoModCache, j("go", "pkg", "mod", "cache", "download")},
			{kindCargoHome, ".cargo"},
			{kindCargoCache, j(".cargo", "registry", "cache", "*")},
			{kindGemDir, j(".gem", "ruby", "*")},
			{kindPubGlobal, j(".pub-cache", "global_packages", "*")},
			{kindPubCache, j(".pub-cache", "hosted", "pub.dev")},
		}
	}

	pkgs, complete := CollectGlobal(context.Background(), nil)
	if !complete {
		t.Error("complete = false, want true")
	}
	byKey := map[string]Package{}
	for _, p := range pkgs {
		byKey[p.Ecosystem+":"+p.Name+"@"+p.Version+":"+p.Scope] = p
	}
	stdlib := "go:stdlib@" + strings.Fields(strings.TrimPrefix(runtime.Version(), "go"))[0] + ":global"
	want := []string{
		"npm:cowsay@1.6.0:global", "npm:npm@10.2.4:global",
		"pypi:black@24.2.0:global", "pypi:numpy@1.26.4:global",
		"nuget:dotnetsay@2.1.4:global", "nuget:newtonsoft.json@13.0.1:cache",
		"maven:org.apache.logging.log4j:log4j-core@2.14.1:cache", "maven:junit:junit@4.13.1:cache",
		"maven:com.example:lib@3.0.0:cache", "maven:com.google.guava:guava@31.1-jre:cache",
		stdlib, "go:github.com/BurntSushi/toml@v1.3.2:cache",
		"cargo:ripgrep@14.1.0:global", "cargo:cargo-edit@0.12.2:global", "cargo:serde@1.0.197:cache",
		"rubygems:rack@2.2.8:global", "rubygems:json@2.6.3:global",
		"pub:async@2.11.0:global", "pub:http@0.13.6:global", "pub:path@1.9.0:cache",
		"cran:jsonlite@1.8.8:global",
	}
	if links {
		want = append(want, "npm:is-odd@3.0.1:global", "npm:@scope/pkg@1.0.0:global")
	}
	for _, k := range want {
		if _, ok := byKey[k]; !ok {
			t.Errorf("missing %s", k)
		}
	}
	for k := range byKey {
		if strings.Contains(k, "outside") || strings.Contains(k, "private") || strings.Contains(k, "stats") ||
			strings.Contains(k, "half") || strings.Contains(k, "sum.golang.org") {
			t.Errorf("unexpected %s", k)
		}
	}
	if t.Failed() {
		t.Logf("got %v", keys(byKey))
	}

	if p := byKey["npm:is-odd@3.0.1:global"]; links && (p.Location != j(pnpm, "is-odd") || p.User != "alice") {
		t.Errorf("pnpm package = %+v, want the link as location", p)
	}
	if p := byKey["maven:junit:junit@4.13.1:cache"]; p.Location != j(m2, "junit", "junit", "4.13.1") {
		t.Errorf("maven location = %q", p.Location)
	}
	if p := byKey[stdlib]; p.Location != j(alice, "go", "bin", "tool") {
		t.Errorf("go binary location = %q", p.Location)
	}

	// A server that hasn't advertised the new ecosystems gets none of them,
	// and their roots aren't read.
	old := Settings{}
	legacy, _ := CollectGlobal(context.Background(), old.Accepts)
	for _, p := range legacy {
		if !old.Accepts(p.Ecosystem) {
			t.Errorf("collected %s for a server that doesn't accept it", p.Ecosystem)
		}
	}
}
