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
