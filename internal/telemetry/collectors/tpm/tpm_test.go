package tpm

import (
	"context"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

var _ tel.Collector = (*Collector)(nil)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != tel.SectionTPM {
		t.Errorf("Name() = %q, want %q", c.Name(), tel.SectionTPM)
	}
	if c.Section() != tel.SectionTPM {
		t.Errorf("Section() = %q, want %q", c.Section(), tel.SectionTPM)
	}
	if c.SchemaVersion() != 1 {
		t.Errorf("SchemaVersion() = %d, want 1", c.SchemaVersion())
	}
}

// TestCapabilityClaimsKeyAndNeverBlamesTheOS mirrors the secure_boot regression
// test: the tpm key was unclaimed, so it inherited the manifest default and
// reported "unavailable_on_os" on Windows hosts that expose Win32_Tpm perfectly
// well. A claimed key must resolve to a state describing the DEVICE — supported,
// not_present, or unsupported — never one describing the operating system.
func TestCapabilityClaimsKeyAndNeverBlamesTheOS(t *testing.T) {
	c := New()
	key, state := c.Capability(context.Background(), tel.CollectorConfig{})

	if key != tel.CapKeyTPM {
		t.Errorf("Capability() key = %q, want %q", key, tel.CapKeyTPM)
	}
	if !state.Valid() {
		t.Errorf("Capability() state = %q is not a valid state", state)
	}
	switch state {
	case tel.CapUnavailableOS:
		t.Errorf("Capability() state = %q; Windows and Linux both expose TPM state, and macOS is not_present", state)
	case tel.CapNotCollected:
		t.Errorf("Capability() state = %q; a collector claimed this key, so it must report a real state", state)
	}
}

// TestProbeRunsOncePerCycle guards the cache: on Windows the probe is a
// PowerShell round-trip, and RunAll calls Capability then Collect back to back.
func TestProbeRunsOncePerCycle(t *testing.T) {
	c := New()
	_, first := c.Capability(context.Background(), tel.CollectorConfig{})
	payload, _ := c.Collect(context.Background(), tel.CollectorConfig{})
	_, second := c.Capability(context.Background(), tel.CollectorConfig{})

	if first != second {
		t.Errorf("capability changed within one cycle: %q then %q", first, second)
	}
	p, ok := payload.(Payload)
	if !ok {
		t.Fatalf("payload type = %T, want tpm.Payload", payload)
	}
	// The payload and the capability come from the same probe, so they cannot
	// disagree about presence.
	if first == tel.CapSupported && !p.Present {
		t.Error("capability says supported but the payload reports no TPM present")
	}
	if first == tel.CapNotPresent && p.Present {
		t.Error("capability says not_present but the payload reports a TPM")
	}
}

func TestParseWindowsTPM(t *testing.T) {
	enabled := true

	tests := []struct {
		name        string
		output      string
		wantOK      bool
		wantEnabled *bool
		wantVersion string
	}{
		{
			name:        "single object",
			output:      `{"IsEnabled_InitialValue":true,"IsActivated_InitialValue":true,"SpecVersion":"2.0, 0, 1.38","ManufacturerIdTxt":"INTC"}`,
			wantOK:      true,
			wantEnabled: &enabled,
			wantVersion: "2.0, 0, 1.38",
		},
		{
			name:        "array form",
			output:      `[{"IsEnabled_InitialValue":true,"SpecVersion":"1.2"}]`,
			wantOK:      true,
			wantEnabled: &enabled,
			wantVersion: "1.2",
		},
		{name: "empty output", output: "   ", wantOK: false},
		{name: "not json", output: "Get-CimInstance : namespace not found", wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseWindowsTPM(tc.output)
			if ok != tc.wantOK {
				t.Fatalf("parseWindowsTPM() ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if got.SpecVersion != tc.wantVersion {
				t.Errorf("SpecVersion = %q, want %q", got.SpecVersion, tc.wantVersion)
			}
			if (got.IsEnabled == nil) != (tc.wantEnabled == nil) {
				t.Errorf("IsEnabled presence = %v, want %v", got.IsEnabled != nil, tc.wantEnabled != nil)
			}
		})
	}
}

// TestAbsentEnabledFieldStaysNil is the safety property: a missing property must
// not become "TPM disabled", which would be a fabricated security finding.
func TestAbsentEnabledFieldStaysNil(t *testing.T) {
	got, ok := parseWindowsTPM(`{"SpecVersion":"2.0"}`)
	if !ok {
		t.Fatal("parseWindowsTPM() failed on a valid object")
	}
	if got.IsEnabled != nil {
		t.Errorf("IsEnabled = %v, want nil for an absent property", *got.IsEnabled)
	}
}

func TestSpecVersion(t *testing.T) {
	tests := map[string]string{
		"2.0, 0, 1.38": "2.0",
		"1.2":          "1.2",
		"":             "",
		"  2.0  ":      "2.0",
	}
	for in, want := range tests {
		if got := specVersion(in); got != want {
			t.Errorf("specVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLinuxVersion(t *testing.T) {
	tests := map[string]string{"2": "2.0", "1": "1.2", "2\n": "2.0", "": "", "9": ""}
	for in, want := range tests {
		if got := linuxVersion(in); got != want {
			t.Errorf("linuxVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCollect_Integration exercises the real platform code on this host.
func TestCollect_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	c := New()
	_, capState := c.Capability(context.Background(), tel.CollectorConfig{})
	payload, res := c.Collect(context.Background(), tel.CollectorConfig{})

	p, ok := payload.(Payload)
	if !ok {
		t.Fatalf("payload type = %T, want tpm.Payload", payload)
	}
	if !p.Present && p.Enabled != nil {
		t.Error("Enabled must stay nil when no TPM is present")
	}

	t.Logf("tpm: capability=%q present=%v version=%q status=%q source=%q",
		capState, p.Present, p.Version, res.Status, res.Source)
}
