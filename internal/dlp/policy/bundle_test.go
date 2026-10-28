package policy

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// sampleBundle is the contract example from sentinel-ops docs/dlp.md.
const sampleBundle = `{
  "schema_version": 1,
  "version": "sha256:abc",
  "enabled": true,
  "poll_interval_seconds": 300,
  "evidence_mode": "masked",
  "modules": {"clipboard": {"enabled": true, "max_scan_bytes": 1048576, "ignore_concealed": true,
    "block_message": "Blocked by SentinelOps: {{detector}}",
    "notify_message": "SentinelOps flagged sensitive data on your clipboard: {{detector}}"}},
  "policies": [{
    "id": "p1", "name": "Block cloud secrets", "severity": "high", "channels": ["clipboard"],
    "action": "block", "match": "any",
    "detectors": [
      {"id": "custom.keywords", "rule_id": "r1", "min_count": 1, "keywords": ["CONFIDENTIAL"], "case_sensitive": false},
      {"id": "custom.regex", "rule_id": "r2", "min_count": 1, "pattern": "(?i)project-falcon-\\d+"},
      {"id": "secrets.all", "rule_id": "r3", "min_count": 1}
    ],
    "exceptions": {"source_apps": ["KeePassXC"]}
  }]
}`

func TestDecode_ContractExample(t *testing.T) {
	b, err := Decode([]byte(sampleBundle))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if b.Version != "sha256:abc" || !b.Enabled || !b.Modules.Clipboard.IgnoreConcealed {
		t.Errorf("bundle = %+v", b)
	}
	p := b.Policies[0]
	if p.Action != ActionBlock || len(p.Detectors) != 3 || p.Detectors[1].Pattern == "" || p.Exceptions.SourceApps[0] != "KeePassXC" {
		t.Errorf("policy = %+v", p)
	}
}

func TestDecode_Rejects(t *testing.T) {
	tests := map[string]string{
		"newer schema":  `{"schema_version": 2, "version": "v"}`,
		"no schema":     `{"version": "v"}`,
		"no version":    `{"schema_version": 1}`,
		"not json":      `<html>`,
		"wrong type":    `{"schema_version": 1, "version": "v", "enabled": "yes"}`,
		"too large":     `{"schema_version": 1, "version": "v", "x": "` + strings.Repeat("a", MaxBundleBytes) + `"}`,
		"array, not {}": `[]`,
	}
	for name, in := range tests {
		if _, err := Decode([]byte(in)); err == nil {
			t.Errorf("%s: Decode succeeded", name)
		}
	}
	_, err := Decode([]byte(`{"schema_version": 2, "version": "v"}`))
	if !errors.Is(err, ErrUnsupportedSchema) {
		t.Errorf("newer schema error = %v, want ErrUnsupportedSchema", err)
	}
}

func TestDecode_Defaults(t *testing.T) {
	b, err := Decode([]byte(`{"schema_version": 1, "version": "v", "evidence_mode": "bogus"}`))
	if err != nil {
		t.Fatal(err)
	}
	if b.EvidenceMode != EvidenceMasked {
		t.Errorf("EvidenceMode = %q, want masked", b.EvidenceMode)
	}
	if b.Modules.Clipboard.MaxScanBytes != DefaultMaxScanBytes {
		t.Errorf("MaxScanBytes = %d", b.Modules.Clipboard.MaxScanBytes)
	}
}

func TestPollInterval(t *testing.T) {
	tests := []struct {
		b    *Bundle
		want time.Duration
	}{
		{nil, 5 * time.Minute},
		{&Bundle{}, 5 * time.Minute},
		{&Bundle{PollIntervalSeconds: 10}, time.Minute},
		{&Bundle{PollIntervalSeconds: 600}, 10 * time.Minute},
		{&Bundle{PollIntervalSeconds: 86400}, time.Hour},
	}
	for _, tt := range tests {
		if got := tt.b.PollInterval(); got != tt.want {
			t.Errorf("PollInterval(%+v) = %v, want %v", tt.b, got, tt.want)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(sampleBundle))
	f.Add([]byte(`{"schema_version": 1, "version": "v", "policies": [{"action": "block", "detectors": [{"id": "custom.regex", "pattern": "("}]}]}`))
	f.Add([]byte(`{"schema_version": 1, "version": "v", "poll_interval_seconds": -1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := Decode(data)
		if err != nil {
			return
		}
		if b.SchemaVersion != SchemaVersion || b.Version == "" {
			t.Fatalf("Decode accepted %+v", b)
		}
		if d := b.PollInterval(); d < MinPollInterval || d > MaxPollInterval {
			t.Fatalf("PollInterval %v out of range", d)
		}
		c := Compile(b)
		for _, p := range c.Policies {
			if p.Action != ActionMonitor && p.Action != ActionBlock {
				t.Fatalf("policy with action %q compiled", p.Action)
			}
		}
	})
}
