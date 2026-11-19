package packages

import (
	"os"
	"path/filepath"
	"testing"
)

// fuzzLockfile seeds a fuzz target with the fixtures and checks that a
// parser of untrusted lockfiles never panics or returns empty fields.
func fuzzLockfile(f *testing.F, parse func([]byte) []nameVersion, seeds ...string) {
	for _, s := range seeds {
		if data, err := os.ReadFile(filepath.Join("testdata", "lockfiles", s+".fixture")); err == nil {
			f.Add(data)
		}
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, nv := range parse(data) {
			if nv.name == "" || nv.version == "" {
				t.Fatalf("empty field: %+v", nv)
			}
		}
	})
}

func FuzzParsePackageLock(f *testing.F) {
	fuzzLockfile(f, parsePackageLock, "package-lock-v1.json", "package-lock-v3.json")
}

func FuzzParseYarnLock(f *testing.F) {
	fuzzLockfile(f, parseYarnLock, "yarn-v1.lock", "yarn-berry.lock")
}

func FuzzParsePnpmLock(f *testing.F) {
	fuzzLockfile(f, parsePnpmLock, "pnpm-v5.yaml", "pnpm-v6.yaml", "pnpm-v9.yaml")
}

func FuzzParseTOMLPackages(f *testing.F) {
	fuzzLockfile(f, parseTOMLPackages, "poetry.lock", "uv.lock")
}

func FuzzParsePipfileLock(f *testing.F) {
	fuzzLockfile(f, parsePipfileLock, "Pipfile.lock")
}

func FuzzParseRequirements(f *testing.F) {
	fuzzLockfile(f, parseRequirements, "requirements.txt")
}

func FuzzParseComposerLock(f *testing.F) {
	fuzzLockfile(f, parseComposerLock, "composer.lock")
}

func FuzzParseBunLock(f *testing.F) { fuzzLockfile(f, parseBunLock, "bun.lock") }

func FuzzParsePdmLock(f *testing.F) { fuzzLockfile(f, parsePdmLock, "pdm.lock") }

func FuzzParsePylock(f *testing.F) { fuzzLockfile(f, parsePylock, "pylock.toml") }

func FuzzParseProjectAssets(f *testing.F) {
	fuzzLockfile(f, parseProjectAssets, "project.assets.json")
}

func FuzzParseNuGetLock(f *testing.F) { fuzzLockfile(f, parseNuGetLock, "packages.lock.json") }

func FuzzParsePackagesConfig(f *testing.F) {
	fuzzLockfile(f, parsePackagesConfig, "packages.config")
}

func FuzzParseGradleLockfile(f *testing.F) {
	fuzzLockfile(f, parseGradleLockfile, "gradle.lockfile")
}

func FuzzParsePom(f *testing.F) { fuzzLockfile(f, parsePom, "pom.xml") }

func FuzzParseGoSum(f *testing.F) { fuzzLockfile(f, parseGoSum, "go.sum") }

func FuzzParseGoMod(f *testing.F) {
	fuzzLockfile(f, func(data []byte) []nameVersion {
		direct, rest := parseGoModule(data, data)
		return append(direct, rest...)
	}, "go.mod")
}

func FuzzParseCargoLock(f *testing.F) { fuzzLockfile(f, parseCargoLock, "Cargo.lock") }

func FuzzParseCargoInstalls(f *testing.F) {
	fuzzLockfile(f, parseCargoInstalls, "crates2.json")
}

func FuzzParseCargoInstallsTOML(f *testing.F) {
	fuzzLockfile(f, parseCargoInstallsTOML, "crates.toml")
}

func FuzzParseGemfileLock(f *testing.F) { fuzzLockfile(f, parseGemfileLock, "Gemfile.lock") }

func FuzzParsePubspecLock(f *testing.F) { fuzzLockfile(f, parsePubspecLock, "pubspec.lock") }

func FuzzParseMixLock(f *testing.F) { fuzzLockfile(f, parseMixLock, "mix.lock") }

func FuzzParsePackageResolved(f *testing.F) {
	fuzzLockfile(f, parsePackageResolved, "Package.resolved-v1", "Package.resolved-v2")
}

func FuzzParseRenvLock(f *testing.F) { fuzzLockfile(f, parseRenvLock, "renv.lock") }

func FuzzFileNames(f *testing.F) {
	for _, s := range []string{"serde-1.0.197.crate", "nokogiri-1.15.0-x86_64-linux.gemspec", "github.com/!a/b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if nv, ok := crateFileName(s); ok && (nv.name == "" || nv.version == "") {
			t.Fatalf("crate %+v", nv)
		}
		if nv, ok := gemspecFileName(s); ok && (nv.name == "" || nv.version == "") {
			t.Fatalf("gem %+v", nv)
		}
		if u, ok := goUnescape(s); ok && len(u) > len(s) {
			t.Fatalf("unescape grew %q to %q", s, u)
		}
	})
}
