package protection

import (
	"context"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

var (
	_ tel.Collector             = (*Collector)(nil)
	_ tel.SubCapabilityReporter = (*Collector)(nil)
)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != tel.SectionProtection {
		t.Errorf("Name() = %q, want %q", c.Name(), tel.SectionProtection)
	}
	if c.Section() != tel.SectionProtection {
		t.Errorf("Section() = %q, want %q", c.Section(), tel.SectionProtection)
	}
	if c.SchemaVersion() != 1 {
		t.Errorf("SchemaVersion() = %d, want 1", c.SchemaVersion())
	}
}

func TestCapabilityOwnsFirewallKey(t *testing.T) {
	c := New()
	key, state := c.Capability(context.Background(), tel.CollectorConfig{})
	if key != tel.CapKeyFirewall {
		t.Errorf("Capability() key = %q, want %q", key, tel.CapKeyFirewall)
	}
	if state != tel.CapSupported {
		t.Errorf("Capability() state = %q; every supported platform has a queryable host firewall", state)
	}
}

// TestSubCapabilitiesAreReportedAndHonest checks the two controls that do not
// exist everywhere are each given an explicit state rather than being left to
// the manifest default — and that the state is never unavailable_on_os, which
// would be a claim about the OS rather than about the control.
func TestSubCapabilitiesAreReportedAndHonest(t *testing.T) {
	subs := New().SubCapabilities(context.Background(), tel.CollectorConfig{})

	for _, key := range []string{tel.CapKeyRealtimeProtection, tel.CapKeyTamperProtection} {
		state, ok := subs[key]
		if !ok {
			t.Errorf("%s was not reported at all; it would fall back to the manifest default", key)
			continue
		}
		if !state.Valid() {
			t.Errorf("%s = %q is not a valid state", key, state)
		}
		if state == tel.CapNotCollected {
			t.Errorf("%s = %q; this collector claims the key, so it owes a real state", key, state)
		}
	}
}

func TestFirewallStateFrom(t *testing.T) {
	tests := []struct {
		name     string
		profiles []Profile
		want     string
	}{
		{"all on", []Profile{{"Domain", true}, {"Private", true}}, StateEnabled},
		{"all off", []Profile{{"Domain", false}, {"Private", false}}, StateDisabled},
		{"mixed", []Profile{{"Domain", true}, {"Public", false}}, StatePartial},
		{"single on", []Profile{{"ufw", true}}, StateEnabled},
		// The important one: nothing reported is not the same as "off".
		{"no profiles", nil, StateUnknown},
		{"empty slice", []Profile{}, StateUnknown},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := firewallStateFrom(tc.profiles); got != tc.want {
				t.Errorf("firewallStateFrom() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestEmptyProfilesAreNeverDisabled states the safety property directly: a
// firewall query that returned nothing must not read as a disabled firewall,
// or every host missing the query tool raises a false critical alert.
func TestEmptyProfilesAreNeverDisabled(t *testing.T) {
	if got := firewallStateFrom(nil); got == StateDisabled {
		t.Fatal("an empty profile list reported the firewall as disabled")
	}
}

func TestParseNetshFirewall(t *testing.T) {
	output := `
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON

Private Profile Settings:
----------------------------------------------------------------------
State                                 OFF

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON
`
	got := parseNetshFirewall(output)
	if len(got) != 3 {
		t.Fatalf("parsed %d profiles, want 3: %+v", len(got), got)
	}
	want := map[string]bool{"Domain": true, "Private": false, "Public": true}
	for _, p := range got {
		enabled, ok := want[p.Name]
		if !ok {
			t.Errorf("unexpected profile %q", p.Name)
			continue
		}
		if p.Enabled != enabled {
			t.Errorf("%s enabled = %v, want %v", p.Name, p.Enabled, enabled)
		}
	}
	if state := firewallStateFrom(got); state != StatePartial {
		t.Errorf("aggregate state = %q, want %q", state, StatePartial)
	}
}

func TestParseNetshFirewallGarbage(t *testing.T) {
	if got := parseNetshFirewall("this is not netsh output"); len(got) != 0 {
		t.Errorf("parsed %d profiles from garbage, want 0", len(got))
	}
}

func TestParseDefenderStatus(t *testing.T) {
	tests := []struct {
		name         string
		output       string
		wantOK       bool
		wantRealtime string
		wantTamper   string
	}{
		{
			name:         "both on",
			output:       `{"RealTimeProtectionEnabled":true,"IsTamperProtected":true}`,
			wantOK:       true,
			wantRealtime: StateEnabled,
			wantTamper:   StateEnabled,
		},
		{
			name:         "realtime off",
			output:       `{"RealTimeProtectionEnabled":false,"IsTamperProtected":true}`,
			wantOK:       true,
			wantRealtime: StateDisabled,
			wantTamper:   StateEnabled,
		},
		{
			// The safety case: absent properties must not read as "off".
			name:         "properties absent",
			output:       `{}`,
			wantOK:       true,
			wantRealtime: StateUnknown,
			wantTamper:   StateUnknown,
		},
		{name: "empty", output: "", wantOK: false},
		{name: "not json", output: "Get-MpComputerStatus : service unavailable", wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseDefenderStatus(tc.output)
			if ok != tc.wantOK {
				t.Fatalf("parseDefenderStatus() ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if state := controlFromBool(got.RealTimeProtectionEnabled, "").State; state != tc.wantRealtime {
				t.Errorf("realtime = %q, want %q", state, tc.wantRealtime)
			}
			if state := controlFromBool(got.IsTamperProtected, "").State; state != tc.wantTamper {
				t.Errorf("tamper = %q, want %q", state, tc.wantTamper)
			}
		})
	}
}

func TestParseUFWStatus(t *testing.T) {
	tests := []struct {
		name        string
		output      string
		wantOK      bool
		wantEnabled bool
	}{
		{"active", "Status: active\n\nTo    Action    From\n", true, true},
		{"inactive", "Status: inactive\n", true, false},
		{"unrecognised", "ufw: command not found", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseUFWStatus(tc.output)
			if ok != tc.wantOK {
				t.Fatalf("parseUFWStatus() ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got.Enabled != tc.wantEnabled {
				t.Errorf("enabled = %v, want %v", got.Enabled, tc.wantEnabled)
			}
		})
	}
}

func TestParseFirewalldState(t *testing.T) {
	if p := parseFirewalldState("running\n"); !p.Enabled {
		t.Error("running firewalld reported as disabled")
	}
	if p := parseFirewalldState("not running\n"); p.Enabled {
		t.Error("stopped firewalld reported as enabled")
	}
}

func TestParseIptablesRules(t *testing.T) {
	if p := parseIptablesRules("Chain INPUT (policy DROP)\n"); !p.Enabled {
		t.Error("a DROP policy was not treated as a firewall")
	}
	// An all-ACCEPT ruleset is not a firewall; calling it one would mask a
	// genuinely unprotected host.
	if p := parseIptablesRules("Chain INPUT (policy ACCEPT)\nChain FORWARD (policy ACCEPT)\n"); p.Enabled {
		t.Error("an all-ACCEPT ruleset was reported as an enabled firewall")
	}
}

func TestParseSocketFilterFW(t *testing.T) {
	if p := parseSocketFilterFW("Firewall is enabled. (State = 1)"); !p.Enabled {
		t.Error("enabled firewall reported as disabled")
	}
	if p := parseSocketFilterFW("Firewall is disabled. (State = 0)"); p.Enabled {
		t.Error("disabled firewall reported as enabled")
	}
}

func TestNormalizeCoercesUnknownValues(t *testing.T) {
	p := Payload{
		Firewall:           Firewall{State: "wat"},
		RealtimeProtection: Control{State: "partial"},
		TamperProtection:   Control{State: ""},
	}
	normalize(&p)

	if p.Firewall.State != StateUnknown {
		t.Errorf("firewall state = %q, want %q", p.Firewall.State, StateUnknown)
	}
	// "partial" is meaningful for a firewall but not for a boolean control.
	if p.RealtimeProtection.State != StateUnknown {
		t.Errorf("realtime state = %q, want %q", p.RealtimeProtection.State, StateUnknown)
	}
	if p.TamperProtection.State != StateUnknown {
		t.Errorf("tamper state = %q, want %q", p.TamperProtection.State, StateUnknown)
	}
}

func TestSortProfilesIsDeterministic(t *testing.T) {
	p := []Profile{{Name: "Public"}, {Name: "Domain"}, {Name: "Private"}}
	sortProfiles(p)
	if p[0].Name != "Domain" || p[1].Name != "Private" || p[2].Name != "Public" {
		t.Errorf("sortProfiles() = %+v", p)
	}
}

// TestCollect_Integration exercises the real platform code on this host.
func TestCollect_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	c := New()
	payload, res := c.Collect(context.Background(), tel.CollectorConfig{})

	p, ok := payload.(Payload)
	if !ok {
		t.Fatalf("payload type = %T, want protection.Payload", payload)
	}

	switch p.Firewall.State {
	case StateEnabled, StateDisabled, StatePartial, StateUnknown:
	default:
		t.Errorf("firewall state = %q is not a defined value", p.Firewall.State)
	}

	t.Logf("protection: firewall=%q profiles=%d realtime=%q tamper=%q status=%q source=%q",
		p.Firewall.State, len(p.Firewall.Profiles),
		p.RealtimeProtection.State, p.TamperProtection.State, res.Status, res.Source)
}
