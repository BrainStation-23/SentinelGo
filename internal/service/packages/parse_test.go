package packages

import (
	"strings"
	"testing"
)

func TestParsePackageJSON(t *testing.T) {
	tests := []struct {
		name, in, wantName, wantVersion string
		ok                              bool
	}{
		{"plain", `{"name":"keyv","version":"4.5.4","dependencies":{"a":"1"}}`, "keyv", "4.5.4", true},
		{"scoped", `{"name":"@tanstack/query-core","version":"5.59.0"}`, "@tanstack/query-core", "5.59.0", true},
		{"trimmed", `{"name":" x ","version":" 1.0.0 "}`, "x", "1.0.0", true},
		{"no version", `{"name":"x"}`, "", "", false},
		{"no name", `{"version":"1.0.0"}`, "", "", false},
		{"not json", `name: x`, "", "", false},
		{"wrong types", `{"name":1,"version":2}`, "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, v, ok := parsePackageJSON([]byte(tt.in))
			if n != tt.wantName || v != tt.wantVersion || ok != tt.ok {
				t.Errorf("parsePackageJSON = %q, %q, %v; want %q, %q, %v", n, v, ok, tt.wantName, tt.wantVersion, tt.ok)
			}
		})
	}
}

func TestParseCoreMetadata(t *testing.T) {
	meta := "Metadata-Version: 2.1\r\nName: Requests\nVersion: 2.32.3\nSummary: HTTP\n\nName: not-a-header\n"
	n, v, ok := parseCoreMetadata([]byte(meta))
	if !ok || n != "Requests" || v != "2.32.3" {
		t.Fatalf("parseCoreMetadata = %q, %q, %v", n, v, ok)
	}

	// The description body after the blank line is never read as headers.
	n, v, ok = parseCoreMetadata([]byte("Name: a\n\nVersion: 1.0\n"))
	if ok {
		t.Errorf("version from the body was used: %q %q", n, v)
	}

	// Case-insensitive keys; the first value wins.
	n, v, ok = parseCoreMetadata([]byte("name: one\nNAME: two\nversion: 3\n"))
	if !ok || n != "one" || v != "3" {
		t.Errorf("parseCoreMetadata = %q, %q, %v; want one, 3", n, v, ok)
	}

	// A huge header line doesn't fail the whole run.
	if _, _, ok := parseCoreMetadata([]byte("X: " + strings.Repeat("a", 1<<20) + "\n")); ok {
		t.Error("over-long line produced a package")
	}
}

func TestParseComposerInstalled(t *testing.T) {
	v1 := `[{"name":"symfony/console","version":"v5.4.1"},{"name":"","version":"1"}]`
	v2 := `{"packages":[{"name":"laravel/installer","version":"5.8.3","version_normalized":"5.8.3.0"},
		{"name":"acme/tool","version":"dev-main"}],"dev":true}`

	got := parseComposerInstalled([]byte(v1))
	if len(got) != 1 || got[0].Name != "symfony/console" || got[0].Version != "5.4.1" {
		t.Errorf("v1 = %+v", got)
	}
	got = parseComposerInstalled([]byte(v2))
	if len(got) != 2 || got[0].Version != "5.8.3" || got[1].Version != "dev-main" {
		t.Errorf("v2 = %+v", got)
	}
	if got := parseComposerInstalled([]byte(`{"packages":"x"}`)); len(got) != 0 {
		t.Errorf("malformed = %+v", got)
	}
}

func TestComposerVersion(t *testing.T) {
	for in, want := range map[string]string{"v1.2.3": "1.2.3", "V2": "2", "1.0": "1.0", "v": "v", "dev-main": "dev-main", "vx": "vx"} {
		if got := composerVersion(in); got != want {
			t.Errorf("composerVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalize(t *testing.T) {
	long := strings.Repeat("a", maxNameLen+1)
	in := []Package{
		{Ecosystem: EcosystemPyPI, Name: "b", Version: "1", Scope: ScopeGlobal, Location: "/p"},
		{Ecosystem: EcosystemNPM, Name: " a ", Version: "1", Scope: ScopeGlobal, Location: "/n"},
		{Ecosystem: EcosystemNPM, Name: "a", Version: "1", Scope: ScopeGlobal, Location: "/n"}, // duplicate after trim
		{Ecosystem: EcosystemNPM, Name: long, Version: "1", Scope: ScopeGlobal, Location: "/n"},
		{Ecosystem: EcosystemNPM, Name: "c", Version: "", Scope: ScopeGlobal, Location: "/n"},
		{Ecosystem: "cargo", Name: "c", Version: "1", Scope: ScopeGlobal, Location: "/n"},
		{Ecosystem: EcosystemNPM, Name: "c", Version: "1", Scope: "weird", Location: "/n"},
		{Ecosystem: EcosystemNPM, Name: "d", Version: "1", Scope: ScopeGlobal, Location: "/n", User: strings.Repeat("u", maxUserLen+1)},
		{Ecosystem: EcosystemNPM, Name: "e\xff", Version: "1", Scope: ScopeGlobal, Location: "/n"},
	}
	out, invalid := normalize(in)
	if invalid != 6 {
		t.Errorf("invalid = %d, want 6", invalid)
	}
	if len(out) != 2 || out[0].Name != "a" || out[1].Ecosystem != EcosystemPyPI {
		t.Errorf("normalize = %+v", out)
	}
}
