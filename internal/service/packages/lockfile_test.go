package packages

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fixture reads testdata/lockfiles/<name>.fixture. The suffix keeps
// dependency scanners (FOSSA, Dependabot, Snyk) from reading the fixtures
// as the repository's own manifests: they pin old versions on purpose.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "lockfiles", name+".fixture"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// got renders parsed entries as sorted "name@version" strings.
func got(nvs []nameVersion) []string {
	out := make([]string, 0, len(nvs))
	for _, nv := range nvs {
		out = append(out, nv.name+"@"+nv.version)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func TestLockfileParsers(t *testing.T) {
	tests := []struct {
		file  string
		parse func([]byte) []nameVersion
		want  []string
	}{
		{"package-lock-v1.json", parsePackageLock, []string{
			"@types/node@20.11.5", "json-buffer@3.0.1", "keyv@4.5.4", "lodash@4.17.21",
		}},
		{"package-lock-v3.json", parsePackageLock, []string{
			"@tanstack/query-core@5.59.0", "gitdep@1.0.0", "json-buffer@3.0.1", "keyv@4.5.4", "string-width@4.2.3",
		}},
		{"yarn-v1.lock", parseYarnLock, []string{"@babel/code-frame@7.12.13", "keyv@4.5.4", "string-width@4.2.3"}},
		{"yarn-berry.lock", parseYarnLock, []string{"@babel/code-frame@7.24.2", "keyv@4.5.4"}},
		{"pnpm-v5.yaml", parsePnpmLock, []string{"@babel/code-frame@7.12.13", "keyv@4.5.4", "react-dom@18.2.0"}},
		{"pnpm-v6.yaml", parsePnpmLock, []string{"@babel/code-frame@7.12.13", "keyv@4.5.4", "react-dom@18.2.0"}},
		{"pnpm-v9.yaml", parsePnpmLock, []string{"@babel/code-frame@7.24.2", "keyv@4.5.4"}},
		{"poetry.lock", parseTOMLPackages, []string{"certifi@2024.2.2", "requests@2.31.0"}},
		{"uv.lock", parseTOMLPackages, []string{"anyio@4.3.0", "httpx@0.27.0"}},
		{"Pipfile.lock", parsePipfileLock, []string{"pytest@8.1.1", "requests@2.31.0"}},
		{"requirements.txt", parseRequirements, []string{"Django@4.2.11", "certifi@2024.2.2", "requests@2.31.0", "urllib3@2.2.1"}},
		{"composer.lock", parseComposerLock, []string{"monolog/monolog@3.5.0", "phpunit/phpunit@10.5.11", "symfony/console@6.4.4"}},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			if g := got(tt.parse(fixture(t, tt.file))); !slices.Equal(g, tt.want) {
				t.Errorf("got  %v\nwant %v", g, tt.want)
			}
		})
	}
}

func TestLockfileParsers_CRLF(t *testing.T) {
	for _, f := range []string{"yarn-v1.lock", "yarn-berry.lock", "pnpm-v9.yaml", "poetry.lock", "requirements.txt"} {
		lf := fixture(t, f)
		crlf := []byte(strings.ReplaceAll(strings.ReplaceAll(string(lf), "\r\n", "\n"), "\n", "\r\n"))
		_, parse, _ := lockfileFor(map[string]string{
			"yarn-v1.lock": "yarn.lock", "yarn-berry.lock": "yarn.lock", "pnpm-v9.yaml": "pnpm-lock.yaml",
			"poetry.lock": "poetry.lock", "requirements.txt": "requirements.txt",
		}[f])
		if a, b := got(parse(lf)), got(parse(crlf)); !slices.Equal(a, b) {
			t.Errorf("%s: CRLF gives %v, LF %v", f, b, a)
		}
	}
}

func TestLockfileFor(t *testing.T) {
	for name, want := range map[string]string{
		"package-lock.json": EcosystemNPM, "npm-shrinkwrap.json": EcosystemNPM, "yarn.lock": EcosystemNPM,
		"pnpm-lock.yaml": EcosystemNPM, "poetry.lock": EcosystemPyPI, "uv.lock": EcosystemPyPI,
		"Pipfile.lock": EcosystemPyPI, "requirements.txt": EcosystemPyPI, "requirements-dev.txt": EcosystemPyPI,
		"composer.lock": EcosystemPackagist,
	} {
		if eco, _, ok := lockfileFor(name); !ok || eco != want {
			t.Errorf("lockfileFor(%q) = %q, %v", name, eco, ok)
		}
	}
	for _, name := range []string{"package.json", "requirements.in", "Pipfile", "composer.json", "lock.yaml"} {
		if _, _, ok := lockfileFor(name); ok {
			t.Errorf("lockfileFor(%q) matched", name)
		}
	}
}

func TestNPMVersion(t *testing.T) {
	for v, ok := range map[string]bool{
		"1.2.3": true, "1.0.0-beta.1": true, "0.0.0-use.local": true,
		"": false, "file:../x": false, "git+https://x": false, "latest": false, "^1.2.3": false, "1.0.0 || 2": false,
	} {
		if _, got := npmVersion(v); got != ok {
			t.Errorf("npmVersion(%q) = %v, want %v", v, got, ok)
		}
	}
}
