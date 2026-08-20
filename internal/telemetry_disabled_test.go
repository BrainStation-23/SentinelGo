package internal

import (
	"os"
	"path/filepath"
	"testing"

	"sentinelgo/internal/config"
	"sentinelgo/internal/scheduler"
	"sentinelgo/internal/store"
)

// newDisabledCfg returns a config with telemetry off, in an empty directory.
func newDisabledCfg(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		Path:             filepath.Join(t.TempDir(), "config.json"),
		DeviceID:         "dev-disabled",
		SupabaseURL:      "https://example.supabase.co",
		SupabaseKey:      "anon",
		TelemetryEnabled: false,
	}
}

// TestTelemetryDisabledRegistersNoTask verifies the scheduler never gets a
// telemetry task when the layer is off.
//
// This is what makes the feature a genuine no-op on an existing fleet: with no
// task registered there is no ticker, no goroutine and no handler invocation.
func TestTelemetryDisabledRegistersNoTask(t *testing.T) {
	mi := NewMainIntegration(newDisabledCfg(t))

	task := mi.buildTelemetryTask()
	if task != nil {
		t.Fatalf("telemetry task was built while disabled: %+v", task.Name)
	}
	if mi.telemetryService != nil {
		t.Error("telemetry service must not be constructed while disabled")
	}
}

// TestTelemetryDisabledCreatesNoDatabases verifies the disabled path performs no
// I/O. Creating the SQLite files would be a visible side effect on every
// endpoint in a fleet that never opted in.
func TestTelemetryDisabledCreatesNoDatabases(t *testing.T) {
	cfg := newDisabledCfg(t)
	dir := filepath.Dir(cfg.Path)

	mi := NewMainIntegration(cfg)
	if task := mi.buildTelemetryTask(); task != nil {
		t.Fatal("expected no task while disabled")
	}

	for _, name := range []string{store.TelemetryStateDBName, store.TelemetryOutboundDBName} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			t.Errorf("telemetry database %s was created while disabled", name)
		} else if !os.IsNotExist(err) {
			t.Errorf("unexpected error checking %s: %v", name, err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read config dir: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("disabled telemetry left files behind: %v", names)
	}
}

// TestTelemetryDisabledHandlerIsInert verifies the second line of defence.
//
// Even if a task were registered — for example because the flag was flipped off
// at runtime after startup — the handler must return immediately without
// collecting, queuing or flushing.
func TestTelemetryDisabledHandlerIsInert(t *testing.T) {
	// Build the service with telemetry ON so a handler exists...
	cfg := newDisabledCfg(t)
	cfg.TelemetryEnabled = true

	mi := NewMainIntegration(cfg)
	task := mi.buildTelemetryTask()
	if task == nil {
		t.Fatal("expected a task when enabled")
	}
	t.Cleanup(func() {
		if mi.telemetryService != nil {
			_ = mi.telemetryService.Close()
		}
	})

	// ...then turn it off, as a config reload would.
	cfg.TelemetryEnabled = false

	// The handler must not touch the network or the queue.
	if err := task.Handler(t.Context(), cfg, nil); err != nil {
		t.Fatalf("disabled handler returned an error: %v", err)
	}

	depth, err := mi.telemetryService.QueueDepth()
	if err != nil {
		t.Fatalf("QueueDepth: %v", err)
	}
	if depth != 0 {
		t.Errorf("disabled handler queued %d message(s)", depth)
	}
}

// TestTelemetryTaskUsesConfiguredInterval confirms the registered task picks up
// the configured cadence rather than a hardcoded one.
func TestTelemetryTaskUsesConfiguredInterval(t *testing.T) {
	cfg := newDisabledCfg(t)
	cfg.TelemetryEnabled = true

	mi := NewMainIntegration(cfg)
	task := mi.buildTelemetryTask()
	if task == nil {
		t.Fatal("expected a task when enabled")
	}
	t.Cleanup(func() {
		if mi.telemetryService != nil {
			_ = mi.telemetryService.Close()
		}
	})

	if task.Name != "telemetry-collect" {
		t.Errorf("task name = %q", task.Name)
	}
	if !task.Enabled {
		t.Error("task should be enabled when telemetry_enabled is true")
	}
	if task.Interval != cfg.GetTelemetryCollectInterval() {
		t.Errorf("interval = %v, want %v", task.Interval, cfg.GetTelemetryCollectInterval())
	}
	var _ *scheduler.Task = task
}
