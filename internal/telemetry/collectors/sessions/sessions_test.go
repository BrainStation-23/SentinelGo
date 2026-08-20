package sessions

import (
	"context"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

var _ tel.Collector = (*Collector)(nil)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != tel.SectionSessions {
		t.Errorf("Name() = %q, want %q", c.Name(), tel.SectionSessions)
	}
	if c.Section() != tel.SectionSessions {
		t.Errorf("Section() = %q, want %q", c.Section(), tel.SectionSessions)
	}
	if c.SchemaVersion() != 1 {
		t.Errorf("SchemaVersion() = %d, want 1", c.SchemaVersion())
	}
}

func TestCapabilityOwnsKeyAndIsValid(t *testing.T) {
	c := New()
	key, state := c.Capability(context.Background(), tel.CollectorConfig{})
	if key != tel.CapKeySessions {
		t.Errorf("Capability() key = %q, want %q", key, tel.CapKeySessions)
	}
	if !state.Valid() {
		t.Errorf("Capability() state = %q is not a valid CapabilityState", state)
	}
}

func TestSortSessions(t *testing.T) {
	s := []Session{
		{Username: "jdoe", SessionName: "rdp-tcp#3"},
		{Username: "administrator", SessionName: "console"},
		{Username: "jdoe", SessionName: "console"},
	}
	sortSessions(s)
	want := []string{"administrator/console", "jdoe/console", "jdoe/rdp-tcp#3"}
	for i, w := range want {
		got := s[i].Username + "/" + s[i].SessionName
		if got != w {
			t.Errorf("position %d = %q, want %q", i, got, w)
		}
	}
}

func TestConsoleUser(t *testing.T) {
	tests := []struct {
		name     string
		sessions []Session
		want     string
	}{
		{"has console", []Session{
			{Username: "jdoe", SessionType: "rdp"},
			{Username: "administrator", SessionType: "console"},
		}, "administrator"},
		{"no console session", []Session{
			{Username: "jdoe", SessionType: "rdp"},
		}, ""},
		{"empty", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := consoleUser(tc.sessions); got != tc.want {
				t.Errorf("consoleUser() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestCollect_Integration exercises the real platform-specific gathering code
// against this host, following the same pattern as the other C1/C2
// collectors: no assumption about who (if anyone) is logged in, just that
// collection completes cleanly and an empty session list is not reported as
// an error.
func TestCollect_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	c := New()
	_, capState := c.Capability(context.Background(), tel.CollectorConfig{})
	if capState != tel.CapSupported {
		t.Skipf("session enumeration unsupported on this host: %s", capState)
	}

	payload, res := c.Collect(context.Background(), tel.CollectorConfig{})
	if !res.Status.OK() {
		t.Errorf("Collect() status = %q, error = %q", res.Status, res.Error)
	}

	p, ok := payload.(Payload)
	if !ok {
		t.Fatalf("payload type = %T, want sessions.Payload", payload)
	}

	t.Logf("sessions: count=%d console_user=%q source=%q status=%q",
		len(p.Sessions), p.ConsoleUser, res.Source, res.Status)
	for _, s := range p.Sessions {
		t.Logf("  %+v", s)
	}
}
