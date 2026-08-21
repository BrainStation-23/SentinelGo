package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"sentinelgo/internal/config"
)

// TestLegacyConfigWithoutPhaseGFieldsIsUnchanged is the backward-compatibility
// guarantee for every deployed agent.
//
// A config.json written before change detection existed has none of the
// telemetry_event_* keys. It must parse cleanly, leave the feature off, and
// leave every pre-existing setting exactly as it was — an upgrade that silently
// switched on a new telemetry path, or reset an operator's tuned intervals,
// would be a far worse regression than the feature is worth.
func TestLegacyConfigWithoutPhaseGFieldsIsUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	legacy := `{
  "supabase_url": "https://example.supabase.co",
  "supabase_key": "anon-key",
  "device_id": "legacy-device",
  "telemetry_enabled": true,
  "telemetry_collect_interval": "20m",
  "telemetry_queue_max_rows": 1234,
  "software_sync_enabled": true,
  "audit_logs_enabled": true,
  "services_sync_enabled": true
}`
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() rejected a pre-Phase-G config: %v", err)
	}

	// The new feature is off.
	if cfg.TelemetryEventsEnabled {
		t.Error("TelemetryEventsEnabled defaulted to true on a config that never mentioned it")
	}

	// Existing settings survive untouched.
	if cfg.DeviceID != "legacy-device" {
		t.Errorf("DeviceID = %q, want %q", cfg.DeviceID, "legacy-device")
	}
	if !cfg.TelemetryEnabled {
		t.Error("TelemetryEnabled was lost")
	}
	if got := cfg.GetTelemetryCollectInterval(); got != 20*time.Minute {
		t.Errorf("TelemetryCollectInterval = %v, want 20m", got)
	}
	if got := cfg.GetTelemetryQueueMaxRows(); got != 1234 {
		t.Errorf("TelemetryQueueMaxRows = %d, want 1234", got)
	}
	if !cfg.SoftwareSyncEnabled || !cfg.AuditLogsEnabled || !cfg.ServicesSyncEnabled {
		t.Error("a Phase B–F feature flag was lost")
	}

	// And the new accessors still return usable values rather than zero, so
	// nothing downstream has to special-case an old config.
	if got := cfg.GetTelemetryEventCooldown(); got <= 0 {
		t.Errorf("cooldown = %v on a legacy config; it must fall back to a default", got)
	}
	if got := cfg.GetTelemetryEventFlapWindow(); got <= 0 {
		t.Errorf("flap window = %v on a legacy config", got)
	}
	if got := cfg.GetTelemetryEventFlapThreshold(); got <= 1 {
		t.Errorf("flap threshold = %d on a legacy config", got)
	}
}

// TestPhaseGFieldsLoadFromConfig covers the opposite direction: every knob is
// readable from JSON, in both the string-duration and numeric forms the
// Duration type accepts.
func TestPhaseGFieldsLoadFromConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := `{
  "supabase_url": "https://example.supabase.co",
  "supabase_key": "anon-key",
  "telemetry_enabled": true,
  "telemetry_events_enabled": true,
  "telemetry_event_debounce": "30s",
  "telemetry_event_cooldown": "5m",
  "telemetry_event_flap_window": "45m",
  "telemetry_event_flap_threshold": 6
}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if !cfg.TelemetryEventsEnabled {
		t.Error("TelemetryEventsEnabled = false, want true")
	}
	if got := cfg.GetTelemetryEventDebounce(); got != 30*time.Second {
		t.Errorf("debounce = %v, want 30s", got)
	}
	if got := cfg.GetTelemetryEventCooldown(); got != 5*time.Minute {
		t.Errorf("cooldown = %v, want 5m", got)
	}
	if got := cfg.GetTelemetryEventFlapWindow(); got != 45*time.Minute {
		t.Errorf("flap window = %v, want 45m", got)
	}
	if got := cfg.GetTelemetryEventFlapThreshold(); got != 6 {
		t.Errorf("flap threshold = %d, want 6", got)
	}
}

// TestPhaseGDefaultsAreSafe pins the shipped defaults. Change detection feeds
// security alerting, so any change to these values should be a deliberate edit
// to this test as well.
func TestPhaseGDefaultsAreSafe(t *testing.T) {
	cfg, err := config.Load(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.TelemetryEventsEnabled {
		t.Error("change detection ships enabled; it must be opt-in")
	}
	if got := cfg.GetTelemetryEventDebounce(); got != 0 {
		t.Errorf("debounce default = %v, want 0 (confirm on the next cycle)", got)
	}
	if got := cfg.GetTelemetryEventCooldown(); got != 10*time.Minute {
		t.Errorf("cooldown default = %v, want 10m", got)
	}
	if got := cfg.GetTelemetryEventFlapWindow(); got != time.Hour {
		t.Errorf("flap window default = %v, want 1h", got)
	}
	if got := cfg.GetTelemetryEventFlapThreshold(); got != 4 {
		t.Errorf("flap threshold default = %d, want 4", got)
	}
}

// TestNegativeEventDurationsAreCoerced: a negative duration is nonsense, and
// letting one through would make the cooldown comparison always true and
// suppress every event after the first.
func TestNegativeEventDurationsAreCoerced(t *testing.T) {
	cfg := &config.Config{
		TelemetryEventDebounce:   config.Duration(-time.Minute),
		TelemetryEventCooldown:   config.Duration(-time.Minute),
		TelemetryEventFlapWindow: config.Duration(-time.Minute),
	}

	if got := cfg.GetTelemetryEventDebounce(); got != 0 {
		t.Errorf("negative debounce = %v, want 0", got)
	}
	if got := cfg.GetTelemetryEventCooldown(); got <= 0 {
		t.Errorf("negative cooldown = %v, want a positive default", got)
	}
	if got := cfg.GetTelemetryEventFlapWindow(); got <= 0 {
		t.Errorf("negative flap window = %v, want a positive default", got)
	}
}
