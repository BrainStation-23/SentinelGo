package secureboot

import (
	"context"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

var _ tel.Collector = (*Collector)(nil)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != tel.SectionSecureBoot {
		t.Errorf("Name() = %q, want %q", c.Name(), tel.SectionSecureBoot)
	}
	if c.Section() != tel.SectionSecureBoot {
		t.Errorf("Section() = %q, want %q", c.Section(), tel.SectionSecureBoot)
	}
	if c.SchemaVersion() != 1 {
		t.Errorf("SchemaVersion() = %d, want 1", c.SchemaVersion())
	}
}

// TestCapabilityClaimsKeyAndNeverBlamesTheOS is the regression test for the
// bug this collector exists to fix.
//
// Before it, nothing filled the secure_boot section, so CapKeySecureBoot kept
// the capability manifest's default and every Windows 11 endpoint reported
// "unavailable_on_os" — a claim that the operating system could not provide
// Secure Boot state, on an operating system that plainly can. Two things must
// hold now and keep holding: the key is claimed by a collector at all, and the
// state is never unavailable_on_os on a platform this agent supports.
func TestCapabilityClaimsKeyAndNeverBlamesTheOS(t *testing.T) {
	c := New()
	key, state := c.Capability(context.Background(), tel.CollectorConfig{})

	if key != tel.CapKeySecureBoot {
		t.Errorf("Capability() key = %q, want %q", key, tel.CapKeySecureBoot)
	}
	if !state.Valid() {
		t.Errorf("Capability() state = %q is not a valid state", state)
	}
	if state == tel.CapUnavailableOS {
		t.Errorf("Capability() state = %q; every supported platform can report Secure Boot", state)
	}
	if state == tel.CapNotCollected {
		t.Errorf("Capability() state = %q; a collector claimed this key, so it must report a real state", state)
	}
}

// TestCapabilityProbeIsCachedWithinACycle guards the reason ProbeCache exists:
// RunAll calls Capability and then Collect back to back, and re-running the
// platform probe for each would double this collector's cost every cycle.
func TestCapabilityProbeIsCachedWithinACycle(t *testing.T) {
	c := New()
	_, first := c.Capability(context.Background(), tel.CollectorConfig{})
	_, second := c.Capability(context.Background(), tel.CollectorConfig{})
	if first != second {
		t.Errorf("cached capability changed between calls: %q then %q", first, second)
	}
}

func TestNormalizeState(t *testing.T) {
	tests := map[string]string{
		StateEnabled:      StateEnabled,
		StateDisabled:     StateDisabled,
		StateUnknown:      StateUnknown,
		"":                StateUnknown,
		"ENABLED":         StateUnknown,
		"partially-maybe": StateUnknown,
	}
	for in, want := range tests {
		if got := normalizeState(in); got != want {
			t.Errorf("normalizeState(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseRegDWORD(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		want    int
		wantErr bool
	}{
		{
			name:   "hex value",
			output: "HKEY_LOCAL_MACHINE\\...\\State\r\n    UEFISecureBootEnabled    REG_DWORD    0x1\r\n",
			want:   1,
		},
		{
			name:   "zero",
			output: "    UEFISecureBootEnabled    REG_DWORD    0x0",
			want:   0,
		},
		{
			name:   "decimal value",
			output: "    UEFISecureBootEnabled    REG_DWORD    1",
			want:   1,
		},
		{
			name:    "value absent",
			output:  "ERROR: The system was unable to find the specified registry key or value.",
			wantErr: true,
		},
		{
			name:    "empty output",
			output:  "",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseRegDWORD(tc.output, "UEFISecureBootEnabled")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseRegDWORD() = %d, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRegDWORD() error = %v", err)
			}
			if got != tc.want {
				t.Errorf("parseRegDWORD() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestMissingValueIsNotDisabled is the safety property that matters most here:
// a registry read that finds nothing must not become "Secure Boot is off",
// which would raise a false security alert on every legacy-BIOS host.
func TestMissingValueIsNotDisabled(t *testing.T) {
	if _, err := parseRegDWORD("nothing here", "UEFISecureBootEnabled"); err == nil {
		t.Fatal("a missing value parsed successfully; it must be an error, not a state")
	}
}

func TestStateFromDWORD(t *testing.T) {
	tests := map[int]string{1: StateEnabled, 0: StateDisabled, 7: StateUnknown, -1: StateUnknown}
	for in, want := range tests {
		if got := stateFromDWORD(in); got != want {
			t.Errorf("stateFromDWORD(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestParseMokutil(t *testing.T) {
	tests := map[string]string{
		"SecureBoot enabled":                      StateEnabled,
		"SecureBoot disabled":                     StateDisabled,
		"This system doesn't support Secure Boot": StateUnknown,
		"": StateUnknown,
	}
	for in, want := range tests {
		if got := parseMokutil(in); got != want {
			t.Errorf("parseMokutil(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseEFIVar(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"enabled", []byte{0x06, 0x00, 0x00, 0x00, 0x01}, StateEnabled},
		{"disabled", []byte{0x06, 0x00, 0x00, 0x00, 0x00}, StateDisabled},
		{"truncated", []byte{0x06, 0x00}, StateUnknown},
		{"empty", nil, StateUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseEFIVar(tc.data); got != tc.want {
				t.Errorf("parseEFIVar() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseBridgeOSSecurity(t *testing.T) {
	tests := map[string]string{
		"Secure Boot: Full Security":    StateEnabled,
		"Secure Boot: Reduced Security": StateEnabled,
		"Secure Boot: No Security":      StateDisabled,
		"Apple T2 Security Chip":        StateUnknown,
		"":                              StateUnknown,
	}
	for in, want := range tests {
		if got := parseBridgeOSSecurity(in); got != want {
			t.Errorf("parseBridgeOSSecurity(%q) = %q, want %q", in, got, want)
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
	if capState != tel.CapSupported {
		t.Skipf("secure boot not readable on this host: %s", capState)
	}

	payload, res := c.Collect(context.Background(), tel.CollectorConfig{})
	p, ok := payload.(Payload)
	if !ok {
		t.Fatalf("payload type = %T, want secureboot.Payload", payload)
	}

	switch p.State {
	case StateEnabled, StateDisabled, StateUnknown:
	default:
		t.Errorf("State = %q, want one of enabled/disabled/unknown", p.State)
	}
	if p.State == StateUnknown && p.Enabled != nil {
		t.Error("Enabled must stay nil while State is unknown")
	}

	t.Logf("secure_boot: state=%q mechanism=%q status=%q source=%q",
		p.State, p.Mechanism, res.Status, res.Source)
}
