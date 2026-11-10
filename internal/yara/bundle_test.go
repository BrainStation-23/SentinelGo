package yara

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const (
	rsID  = "6f1c2a40-1111-4c3b-9a55-0123456789ab"
	rsID2 = "6f1c2a40-2222-4c3b-9a55-0123456789ab"
	schID = "a0b1c2d3-3333-4e5f-8a9b-0123456789ab"
	hash  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// sampleBundle is contract §2's example.
const sampleBundle = `{
  "schema_version": 1,
  "version": "v-abc",
  "enabled": true,
  "engine": { "name": "go-yara", "min_version": "0.9.0" },
  "rulesets": [
    { "id": "` + rsID + `", "name": "Hack tools", "revision": 3,
      "storage_path": "yara/default/` + rsID + `/3.yar",
      "sha256": "` + hash + `", "size": 18233,
      "severity": "high", "tags": ["hacktool"] }
  ],
  "schedules": [
    { "id": "` + schID + `", "preset": "custom",
      "paths": { "windows": ["C:\\Users\\*\\Downloads"], "darwin": [], "linux": ["/srv"] },
      "exclusions": { "windows": [], "darwin": [], "linux": ["/srv/cache"] },
      "every_hours": 24, "jitter_minutes": 120,
      "ruleset_ids": ["` + rsID + `"] }
  ],
  "limits": {
    "max_file_bytes": 104857600, "per_file_timeout_ms": 10000,
    "max_cpu_percent": 25, "skip_on_battery": true,
    "include_network_mounts": false, "include_removable": false,
    "max_files_per_scan": 500000, "max_scan_minutes": 240
  },
  "evidence": { "path_mode": "full" },
  "a_future_key": { "ignored": true }
}`

func TestDecode_Sample(t *testing.T) {
	b, err := Decode([]byte(sampleBundle))
	if err != nil {
		t.Fatal(err)
	}
	want := &Bundle{
		SchemaVersion: 1, Version: "v-abc", Enabled: true,
		Engine: Engine{Name: "go-yara", MinVersion: "0.9.0"},
		Rulesets: []Ruleset{{
			ID: rsID, Name: "Hack tools", Revision: 3,
			StoragePath: "yara/default/" + rsID + "/3.yar",
			SHA256:      hash, Size: 18233, Severity: "high", Tags: []string{"hacktool"},
		}},
		Schedules: []Schedule{{
			ID: schID, Preset: PresetCustom,
			Paths:      OSPaths{Windows: []string{`C:\Users\*\Downloads`}, Darwin: []string{}, Linux: []string{"/srv"}},
			Exclusions: OSPaths{Windows: []string{}, Darwin: []string{}, Linux: []string{"/srv/cache"}},
			EveryHours: 24, JitterMinutes: 120,
			RulesetIDs: []string{rsID},
		}},
		Limits:   DefaultLimits(),
		Evidence: Evidence{PathMode: PathModeFull},
	}
	if !reflect.DeepEqual(b, want) {
		t.Fatalf("decoded\n%+v\nwant\n%+v", b, want)
	}
	if b.Evidence.HashPaths() {
		t.Error("full path mode reported as hashed")
	}
	if got := b.Schedules[0].Paths.For("linux"); !reflect.DeepEqual(got, []string{"/srv"}) {
		t.Errorf("For(linux) = %v", got)
	}
	if got := b.Schedules[0].Paths.For("plan9"); got != nil {
		t.Errorf("For(plan9) = %v, want nil", got)
	}
}

func TestDecode_RoundTrip(t *testing.T) {
	b, err := Decode([]byte(sampleBundle))
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(b, again) {
		t.Fatalf("round trip changed the bundle:\n%+v\n%+v", b, again)
	}
}

// edit decodes the sample, lets fn change it as a generic map, and re-encodes.
func edit(t *testing.T, fn func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(sampleBundle), &m); err != nil {
		t.Fatal(err)
	}
	fn(m)
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func ruleset0(m map[string]any) map[string]any {
	return m["rulesets"].([]any)[0].(map[string]any)
}

func schedule0(m map[string]any) map[string]any {
	return m["schedules"].([]any)[0].(map[string]any)
}

func TestDecode_Rejects(t *testing.T) {
	cases := []struct {
		name string
		fn   func(m map[string]any)
		want error
	}{
		{"no schema", func(m map[string]any) { delete(m, "schema_version") }, ErrUnsupportedSchema},
		{"schema 2", func(m map[string]any) { m["schema_version"] = 2 }, ErrUnsupportedSchema},
		{"no version", func(m map[string]any) { m["version"] = "" }, ErrInvalidBundle},
		{"long version", func(m map[string]any) { m["version"] = strings.Repeat("v", MaxVersionLen+1) }, ErrInvalidBundle},
		{"bad ruleset id", func(m map[string]any) { ruleset0(m)["id"] = "nope" }, ErrInvalidBundle},
		{"bad sha", func(m map[string]any) { ruleset0(m)["sha256"] = "abc" }, ErrInvalidBundle},
		{"negative size", func(m map[string]any) { ruleset0(m)["size"] = -1 }, ErrInvalidBundle},
		{"ruleset too big", func(m map[string]any) { ruleset0(m)["size"] = MaxRulesetBytes + 1 }, ErrTooLarge},
		{"path escape", func(m map[string]any) { ruleset0(m)["storage_path"] = "yara/../secrets.txt" }, ErrInvalidBundle},
		{"path outside", func(m map[string]any) { ruleset0(m)["storage_path"] = "other/x.yar" }, ErrInvalidBundle},
		{"path absolute", func(m map[string]any) { ruleset0(m)["storage_path"] = "/yara/x.yar" }, ErrInvalidBundle},
		{"path backslash", func(m map[string]any) { ruleset0(m)["storage_path"] = `yara\x.yar` }, ErrInvalidBundle},
		{"path double slash", func(m map[string]any) { ruleset0(m)["storage_path"] = "yara//x.yar" }, ErrInvalidBundle},
		{"duplicate ruleset", func(m map[string]any) {
			m["rulesets"] = append(m["rulesets"].([]any), m["rulesets"].([]any)[0])
		}, ErrInvalidBundle},
		{"bad preset", func(m map[string]any) { schedule0(m)["preset"] = "deep" }, ErrInvalidBundle},
		{"zero interval", func(m map[string]any) { schedule0(m)["every_hours"] = 0 }, ErrInvalidBundle},
		{"negative jitter", func(m map[string]any) { schedule0(m)["jitter_minutes"] = -5 }, ErrInvalidBundle},
		{"schedule names missing ruleset", func(m map[string]any) { schedule0(m)["ruleset_ids"] = []any{rsID2} }, ErrInvalidBundle},
		{"not json", nil, ErrInvalidBundle},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(`{"schema_version":1,`)
			if tc.fn != nil {
				raw = edit(t, tc.fn)
			}
			_, err := Decode(raw)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDecode_SizeCaps(t *testing.T) {
	t.Run("bundle JSON", func(t *testing.T) {
		raw := edit(t, func(m map[string]any) { m["padding"] = strings.Repeat("x", MaxBundleBytes) })
		if _, err := Decode(raw); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("err = %v, want ErrTooLarge", err)
		}
	})
	t.Run("ruleset count", func(t *testing.T) {
		raw := edit(t, func(m map[string]any) {
			m["schedules"] = []any{}
			var rs []any
			for i := range MaxRulesets + 1 {
				r := map[string]any{}
				for k, v := range ruleset0(m) {
					r[k] = v
				}
				r["id"] = fmt.Sprintf("6f1c2a40-1111-4c3b-9a55-%012d", i)
				rs = append(rs, r)
			}
			m["rulesets"] = rs
		})
		if _, err := Decode(raw); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("err = %v, want ErrTooLarge", err)
		}
	})
	t.Run("total rule bytes", func(t *testing.T) {
		raw := edit(t, func(m map[string]any) {
			m["schedules"] = []any{}
			var rs []any
			for i := range 5 { // 5 x 5 MB > 20 MB
				r := map[string]any{}
				for k, v := range ruleset0(m) {
					r[k] = v
				}
				r["id"] = fmt.Sprintf("6f1c2a40-1111-4c3b-9a55-%012d", i)
				r["size"] = MaxRulesetBytes
				rs = append(rs, r)
			}
			m["rulesets"] = rs
		})
		if _, err := Decode(raw); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("err = %v, want ErrTooLarge", err)
		}
	})
	t.Run("exactly at the caps", func(t *testing.T) {
		raw := edit(t, func(m map[string]any) {
			m["schedules"] = []any{}
			var rs []any
			for i := range 4 { // 4 x 5 MB = 20 MB
				r := map[string]any{}
				for k, v := range ruleset0(m) {
					r[k] = v
				}
				r["id"] = fmt.Sprintf("6f1c2a40-1111-4c3b-9a55-%012d", i)
				r["size"] = MaxRulesetBytes
				rs = append(rs, r)
			}
			m["rulesets"] = rs
		})
		if _, err := Decode(raw); err != nil {
			t.Fatal(err)
		}
	})
}

func TestDecode_DisabledIgnoresRulesets(t *testing.T) {
	// A disabled bundle's rulesets and schedules don't matter, even
	// malformed ones: the agent stops scanning and drops its rules.
	raw := edit(t, func(m map[string]any) {
		m["enabled"] = false
		ruleset0(m)["id"] = "nope"
	})
	b, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if b.Enabled || b.Rulesets != nil || b.Schedules != nil {
		t.Fatalf("disabled bundle kept rules: %+v", b)
	}
	if b.Limits != DefaultLimits() {
		t.Errorf("limits = %+v", b.Limits)
	}
}

func TestDecode_LimitDefaults(t *testing.T) {
	raw := edit(t, func(m map[string]any) {
		m["limits"] = map[string]any{"max_cpu_percent": 400, "max_file_bytes": -1, "include_removable": true}
	})
	b, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := DefaultLimits()
	want.IncludeRemovable = true
	if b.Limits != want {
		t.Fatalf("limits = %+v, want %+v", b.Limits, want)
	}
	raw = edit(t, func(m map[string]any) { delete(m, "limits") })
	if b, err = Decode(raw); err != nil {
		t.Fatal(err)
	}
	if b.Limits != DefaultLimits() {
		t.Fatalf("missing limits = %+v, want defaults", b.Limits)
	}
}

func TestEvidence_UnknownModeHashes(t *testing.T) {
	for mode, hashed := range map[string]bool{"full": false, "hashed": true, "": true, "partial": true} {
		if got := (Evidence{PathMode: mode}).HashPaths(); got != hashed {
			t.Errorf("HashPaths(%q) = %v, want %v", mode, got, hashed)
		}
	}
}

func TestRulesetsFor(t *testing.T) {
	b := &Bundle{Rulesets: []Ruleset{{ID: rsID}, {ID: rsID2}}}
	if got := b.RulesetsFor(nil); len(got) != 2 {
		t.Errorf("nil ids: %d rulesets, want all", len(got))
	}
	got := b.RulesetsFor([]string{strings.ToUpper(rsID2), "unknown"})
	if len(got) != 1 || got[0].ID != rsID2 {
		t.Errorf("RulesetsFor = %+v", got)
	}
	if got := b.RulesetsFor([]string{}); len(got) != 0 {
		t.Errorf("empty ids: %d rulesets, want none", len(got))
	}
}
