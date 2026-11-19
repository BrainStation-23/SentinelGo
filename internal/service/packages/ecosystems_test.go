package packages

import (
	"slices"
	"testing"
)

func TestEcosystemParsers(t *testing.T) {
	tests := []struct {
		file  string
		parse func([]byte) []nameVersion
		want  []string
	}{
		{"bun.lock", parseBunLock, []string{
			"@tanstack/query-core@5.59.0", "json-buffer@3.0.0", "json-buffer@3.0.1", "keyv@4.5.4", "lodash@4.17.21",
		}},
		{"pdm.lock", parsePdmLock, []string{"certifi@2024.2.2", "requests@2.31.0"}},
		{"pylock.toml", parsePylock, []string{"attrs@25.1.0", "cattrs@24.1.2"}},
		{"project.assets.json", parseProjectAssets, []string{"Newtonsoft.Json@13.0.1", "System.Text.Json@8.0.4"}},
		{"packages.lock.json", parseNuGetLock, []string{"Microsoft.Extensions.Logging.Abstractions@8.0.0", "Serilog@3.1.1"}},
		{"packages.config", parsePackagesConfig, []string{"EntityFramework@6.4.4", "log4net@2.0.8"}},
		{"gradle.lockfile", parseGradleLockfile, []string{
			"com.fasterxml.jackson.core:jackson-databind@2.13.4.2", "com.google.guava:guava@31.1-jre",
			"org.apache.logging.log4j:log4j-core@2.14.1",
		}},
		{"pom.xml", parsePom, []string{
			"com.example:app-core@2.0.0", "junit:junit@4.13.1", "org.apache.logging.log4j:log4j-core@2.14.1",
			"org.springframework:spring-core@5.3.20",
		}},
		{"Cargo.lock", parseCargoLock, []string{"serde@1.0.197", "serde_derive@1.0.197"}},
		{"crates2.json", parseCargoInstalls, []string{"cargo-edit@0.12.2", "ripgrep@14.1.0"}},
		{"crates.toml", parseCargoInstallsTOML, []string{"ripgrep@13.0.0"}},
		{"Gemfile.lock", parseGemfileLock, []string{
			"actionpack@7.1.3", "nokogiri@1.15.0", "racc@1.7.3", "rack-test@2.1.0", "rack@2.2.8",
		}},
		{"pubspec.lock", parsePubspecLock, []string{"async@2.11.0", "http@0.13.6"}},
		{"mix.lock", parseMixLock, []string{"decimal@2.1.1", "jason@1.4.1", "plug@1.15.3"}},
		{"Package.resolved-v1", parsePackageResolved, []string{"https://github.com/Alamofire/Alamofire.git@5.8.1"}},
		{"Package.resolved-v2", parsePackageResolved, []string{
			"git@github.com:apple/swift-log.git@1.5.4", "https://github.com/apple/swift-nio.git@2.62.0",
		}},
		{"renv.lock", parseRenvLock, []string{"data.table@1.15.0", "jsonlite@1.8.8", "rlang@1.1.3"}},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			if g := got(tt.parse(fixture(t, tt.file))); !slices.Equal(g, tt.want) {
				t.Errorf("got  %v\nwant %v", g, tt.want)
			}
		})
	}
}

func TestParseGoModule(t *testing.T) {
	direct, rest := parseGoModule(fixture(t, "go.mod"), fixture(t, "go.sum"))
	if g, want := got(direct), []string{
		"github.com/BurntSushi/toml@v1.3.2", "github.com/new/thing@v1.1.0", "github.com/quoted/mod@v0.2.0",
		"golang.org/x/net@v0.17.0",
	}; !slices.Equal(g, want) {
		t.Errorf("direct = %v\nwant     %v", g, want)
	}
	if g, want := got(rest), []string{"golang.org/x/text@v0.13.0"}; !slices.Equal(g, want) {
		t.Errorf("rest = %v, want %v", g, want)
	}
	// Without go.sum, go.mod still gives the direct requirements.
	if d, r := parseGoModule(fixture(t, "go.mod"), nil); len(d) != 4 || len(r) != 0 {
		t.Errorf("go.mod alone = %v, %v", d, r)
	}
}

func TestParseGoMod_VersionedReplace(t *testing.T) {
	mod := []byte("module m\nrequire a.com/x v1.0.0\nrequire a.com/y v2.0.0\nreplace a.com/x v1.0.0 => b.com/x v1.0.1\nreplace a.com/y v9.9.9 => b.com/y v9.9.9\n")
	direct, _ := parseGoModule(mod, nil)
	if g, want := got(direct), []string{"a.com/y@v2.0.0", "b.com/x@v1.0.1"}; !slices.Equal(g, want) {
		t.Errorf("got %v, want %v", g, want)
	}
}

func TestGoUnescape(t *testing.T) {
	for in, want := range map[string]string{
		"github.com/!burnt!sushi/toml": "github.com/BurntSushi/toml",
		"golang.org/x/net":             "golang.org/x/net",
		"v1.0.0-!r!c1":                 "v1.0.0-RC1",
	} {
		if g, ok := goUnescape(in); !ok || g != want {
			t.Errorf("goUnescape(%q) = %q, %v; want %q", in, g, ok, want)
		}
	}
	for _, bad := range []string{"github.com/Upper", "trailing!", "a!1"} {
		if _, ok := goUnescape(bad); ok {
			t.Errorf("goUnescape(%q) accepted", bad)
		}
	}
}

func TestCrateFileName(t *testing.T) {
	for in, want := range map[string]string{
		"serde-1.0.197.crate":       "serde@1.0.197",
		"md-5-0.10.6.crate":         "md-5@0.10.6",
		"tokio-1.0.0-alpha.1.crate": "tokio@1.0.0-alpha.1",
		"foo-bar-2.0.0-1.crate":     "foo-bar@2.0.0-1",
		"proc-macro2-1.0.78.crate":  "proc-macro2@1.0.78",
		"x25519-dalek-2.0.1.crate":  "x25519-dalek@2.0.1",
	} {
		nv, ok := crateFileName(in)
		if !ok || nv.name+"@"+nv.version != want {
			t.Errorf("crateFileName(%q) = %+v, %v; want %s", in, nv, ok, want)
		}
	}
	for _, bad := range []string{"serde.crate", "serde-1.0.197.tar.gz", "-1.0.0.crate"} {
		if nv, ok := crateFileName(bad); ok {
			t.Errorf("crateFileName(%q) = %+v", bad, nv)
		}
	}
}

func TestGemspecFileName(t *testing.T) {
	for in, want := range map[string]string{
		"rack-2.2.8.gemspec":                     "rack@2.2.8",
		"rack-test-2.1.0.gemspec":                "rack-test@2.1.0",
		"nokogiri-1.15.0-x86_64-linux.gemspec":   "nokogiri@1.15.0",
		"net-imap-0.4.9.1.gemspec":               "net-imap@0.4.9.1",
		"rails-7.1.0.rc1.gemspec":                "rails@7.1.0.rc1",
		"iso-639-0.3.8.gemspec":                  "iso-639@0.3.8",
		"ffi-1.15.5-universal-darwin-22.gemspec": "ffi@1.15.5",
	} {
		nv, ok := gemspecFileName(in)
		if !ok || nv.name+"@"+nv.version != want {
			t.Errorf("gemspecFileName(%q) = %+v, %v; want %s", in, nv, ok, want)
		}
	}
	for _, bad := range []string{"rack.gemspec", "rack-2.2.8.gem", "2.2.8.gemspec"} {
		if nv, ok := gemspecFileName(bad); ok {
			t.Errorf("gemspecFileName(%q) = %+v", bad, nv)
		}
	}
}

func TestParseDescription(t *testing.T) {
	cran := "Package: jsonlite\nVersion: 1.8.8\nTitle: A Simple and Robust JSON Parser\nDescription: A reasonably fast JSON parser\n    and generator.\nRepository: CRAN\nNeedsCompilation: yes\n"
	if n, v, ok := parseDescription([]byte(cran)); !ok || n != "jsonlite" || v != "1.8.8" {
		t.Errorf("CRAN = %q %q %v", n, v, ok)
	}
	for name, desc := range map[string]string{
		"base":         "Package: stats\nVersion: 4.3.2\nPriority: base\n",
		"bioconductor": "Package: Biobase\nVersion: 2.62.0\nbiocViews: Infrastructure\n",
		"github":       "Package: ghpkg\nVersion: 0.0.1\nRemoteType: github\n",
	} {
		if n, v, ok := parseDescription([]byte(desc)); ok {
			t.Errorf("%s = %q %q, want skipped", name, n, v)
		}
	}
}

func TestRequirementsPinned(t *testing.T) {
	for body, want := range map[string]bool{
		"requests==2.31.0\ncertifi==2024.2.2\n":                 true,
		"-c constraints.txt\nrequests==2.31.0 --hash=sha256:aa": true,
		"-r base.txt\nrequests==2.31.0\n":                       false, // base.txt's pins are unknown
		"requests>=2\n":                                         false,
		"requests==2.31.0\nflask\n":                             false,
		"-e .\nrequests==2.31.0\n":                              false,
		"# only comments\n":                                     false,
		"pkg @ https://example.com/pkg.whl\n":                   false,
	} {
		if g := requirementsPinned([]byte(body)); g != want {
			t.Errorf("requirementsPinned(%q) = %v, want %v", body, g, want)
		}
	}
}

func TestParseMixLock_PrivateDependency(t *testing.T) {
	lock := []byte(`%{
  "public_pkg": {:hex, :public_pkg, "1.0.0", "aa", [:mix], [{:private_pkg, "~> 1.0", [hex: :private_pkg, repo: "hexpm:acme", optional: false]}], "hexpm", "bb"},
  "private_pkg": {:hex, :private_pkg, "1.0.0", "cc", [:mix], [], "hexpm:acme", "dd"},
  "old_format": {:hex, :old_format, "0.1.0", "ee", [:mix], [], "hexpm"},
  "custom_repo": {:hex, :custom_repo, "2.0.0", "ff", [:mix], [], "acme_repo", "11"},
  "custom_old": {:hex, :custom_old, "2.0.0", "ff", [:mix], [], "acme_repo"},
  "no_repo": {:hex, :no_repo, "0.0.1", "22", [:mix], []},
  "oldest": {:hex, :oldest, "0.0.2", "33"},
}`)
	if g, want := got(parseMixLock(lock)), []string{"no_repo@0.0.1", "old_format@0.1.0", "oldest@0.0.2", "public_pkg@1.0.0"}; !slices.Equal(g, want) {
		t.Errorf("got %v, want %v", g, want)
	}
}

func TestParseBunLock_CommentAfterTrailingComma(t *testing.T) {
	lock := []byte("{\"packages\": {\"a\": [\"a@1.0.0\"], // comment\n /* block */ }, }")
	if g := got(parseBunLock(lock)); !slices.Equal(g, []string{"a@1.0.0"}) {
		t.Errorf("got %v", g)
	}
}

func TestJSONCToJSON(t *testing.T) {
	in := `{"a": [1, 2,], // comment
"b": "x,]//y", /* block */ "c": {"d": 1,},}`
	want := `{"a": [1, 2], 
"b": "x,]//y",  "c": {"d": 1}}`
	if g := string(jsoncToJSON([]byte(in))); g != want {
		t.Errorf("got  %q\nwant %q", g, want)
	}
}

func TestSettingsAccepts(t *testing.T) {
	legacy := Settings{}
	if !legacy.Accepts(EcosystemNPM) || legacy.Accepts(EcosystemNuGet) {
		t.Error("a server without an ecosystems list must accept npm, pypi and packagist only")
	}
	all := Settings{Ecosystems: []string{EcosystemNuGet, EcosystemNPM}}
	if !all.Accepts(EcosystemNuGet) || all.Accepts(EcosystemPyPI) {
		t.Error("the server's list decides")
	}
	if (Settings{Ecosystems: []string{}}).Accepts(EcosystemNPM) {
		t.Error("an empty list accepts nothing")
	}
	pkgs := []Package{{Ecosystem: EcosystemNPM}, {Ecosystem: EcosystemGo}, {Ecosystem: EcosystemPyPI}}
	if g := legacy.accepted(pkgs); len(g) != 2 || g[1].Ecosystem != EcosystemPyPI {
		t.Errorf("accepted = %+v", g)
	}
}
