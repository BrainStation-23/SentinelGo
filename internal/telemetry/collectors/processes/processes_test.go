package processes

import (
	"context"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

var _ tel.Collector = (*Collector)(nil)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != tel.SectionProcesses {
		t.Errorf("Name() = %q, want %q", c.Name(), tel.SectionProcesses)
	}
	if c.Section() != tel.SectionProcesses {
		t.Errorf("Section() = %q, want %q", c.Section(), tel.SectionProcesses)
	}
	if c.SchemaVersion() != 1 {
		t.Errorf("SchemaVersion() = %d, want 1", c.SchemaVersion())
	}
}

func TestCapability(t *testing.T) {
	c := New()
	key, state := c.Capability(context.Background(), tel.CollectorConfig{})
	if key != tel.CapKeyProcesses {
		t.Errorf("Capability() key = %q, want %q", key, tel.CapKeyProcesses)
	}
	if state != tel.CapSupported {
		t.Errorf("Capability() state = %q, want %q", state, tel.CapSupported)
	}
}

func TestSortProcesses(t *testing.T) {
	p := []Process{{PID: 300}, {PID: 10}, {PID: 200}}
	sortProcesses(p)
	want := []int32{10, 200, 300}
	for i, w := range want {
		if p[i].PID != w {
			t.Errorf("position %d = %d, want %d", i, p[i].PID, w)
		}
	}
}

// TestCollect_Integration exercises the real gopsutil-backed gathering code
// against this host's actual process table.
func TestCollect_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	c := New()
	payload, res := c.Collect(context.Background(), tel.CollectorConfig{})
	if !res.Status.OK() {
		t.Errorf("Collect() status = %q, error = %q", res.Status, res.Error)
	}

	p, ok := payload.(Payload)
	if !ok {
		t.Fatalf("payload type = %T, want processes.Payload (a bare slice)", payload)
	}
	if len(p) == 0 {
		t.Error("no processes reported; every real host has many")
	}

	for _, proc := range p {
		if proc.Cmdline != "" {
			t.Errorf("pid %d has a non-empty Cmdline even though CollectProcessCmdline was not set", proc.PID)
		}
	}

	t.Logf("processes: count=%d source=%q status=%q", len(p), res.Source, res.Status)
	if len(p) > 0 {
		t.Logf("  sample: %+v", p[0])
	}
}

// TestCollect_CmdlineOptIn confirms command lines are only captured when the
// config explicitly opts in — a security-relevant default (command lines
// routinely carry tokens/passwords/connection strings as arguments).
func TestCollect_CmdlineOptIn(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	c := New()
	payload, res := c.Collect(context.Background(), tel.CollectorConfig{CollectProcessCmdline: true})
	if !res.Status.OK() {
		t.Fatalf("Collect() status = %q, error = %q", res.Status, res.Error)
	}

	p := payload.(Payload)
	haveCmdline := false
	for _, proc := range p {
		if proc.Cmdline != "" {
			haveCmdline = true
			break
		}
	}
	if !haveCmdline {
		t.Error("no process had a Cmdline populated even with CollectProcessCmdline=true")
	}
}

// TestCmdlineSubCapabilityDistinguishesDisabledFromUnavailable is the
// regression test for a misleading status.
//
// processes.cmdline used to be unclaimed, so it inherited the capability
// manifest's default and reached the backend as "unavailable_on_os" — telling
// operators that the platform could not provide process command lines. Every
// platform this agent targets can; the agent is configured not to. The two must
// stay distinguishable, because one is a policy decision an admin can reverse
// and the other is a dead end.
func TestCmdlineSubCapabilityDistinguishesDisabledFromUnavailable(t *testing.T) {
	tests := []struct {
		name string
		cfg  tel.CollectorConfig
		want tel.CapabilityState
	}{
		{"off by default", tel.CollectorConfig{}, tel.CapDisabled},
		{"explicitly off", tel.CollectorConfig{CollectProcessCmdline: false}, tel.CapDisabled},
		{"enabled by config", tel.CollectorConfig{CollectProcessCmdline: true}, tel.CapSupported},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			subs := New().SubCapabilities(context.Background(), tc.cfg)

			got, ok := subs[tel.CapKeyProcessesCmdline]
			if !ok {
				t.Fatalf("%s was not reported; it would fall back to the manifest default",
					tel.CapKeyProcessesCmdline)
			}
			if got != tc.want {
				t.Errorf("cmdline capability = %q, want %q", got, tc.want)
			}
			if got == tel.CapUnavailableOS {
				t.Error("cmdline capability blamed the operating system for a config decision")
			}
		})
	}
}

// TestCmdlineCapabilityNeverGatesTheProcessList guards the reason this is a
// sub-capability rather than the collector's primary key: returning a
// non-supported state from Capability makes RunAll skip Collect entirely, which
// would drop the whole process inventory whenever command lines are off — which
// is by default, on every endpoint.
func TestCmdlineCapabilityNeverGatesTheProcessList(t *testing.T) {
	key, state := New().Capability(context.Background(), tel.CollectorConfig{CollectProcessCmdline: false})
	if key != tel.CapKeyProcesses {
		t.Errorf("primary key = %q, want %q", key, tel.CapKeyProcesses)
	}
	if state != tel.CapSupported {
		t.Fatalf("primary capability = %q with cmdline disabled; the process list must stay collected", state)
	}
}

// TestCmdlineIsOffByDefault pins the privacy default in a test, so enabling it
// can only ever be a deliberate change to this line.
func TestCmdlineIsOffByDefault(t *testing.T) {
	var zero tel.CollectorConfig
	if zero.CollectProcessCmdline {
		t.Fatal("command-line capture defaulted to on")
	}
	if got := New().SubCapabilities(context.Background(), zero)[tel.CapKeyProcessesCmdline]; got != tel.CapDisabled {
		t.Fatalf("default cmdline capability = %q, want %q", got, tel.CapDisabled)
	}
}
