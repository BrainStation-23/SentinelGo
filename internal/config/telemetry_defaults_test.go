package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeConfig writes a minimal valid config.json containing the given extra
// keys and loads it.
func writeConfig(t *testing.T, extra map[string]any) *Config {
	t.Helper()

	base := map[string]any{
		"supabase_url":               "https://example.supabase.co",
		"supabase_key":               "anon-key",
		"device_id":                  "dev-1",
		"agent_id":                   "agent-1",
		"agent_secret":               "secret",
		"update_interval":            "5m",
		"auto_update_interval":       "1h",
		"agent_info_update_interval": "5m",
		"task_polling_interval":      "5m",
	}
	for k, v := range extra {
		base[k] = v
	}

	data, err := json.Marshal(base)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

// TestTelemetryDefaults pins the shipped defaults.
//
// The telemetry layer defaults to OFF so that adding it to an existing fleet is
// a no-op until an operator opts in and the backend contract exists.
func TestTelemetryDefaults(t *testing.T) {
	cfg := writeConfig(t, nil)

	if cfg.TelemetryEnabled {
		t.Error("telemetry_enabled must default to false")
	}
	if got := cfg.GetTelemetryCollectInterval(); got != 15*time.Minute {
		t.Errorf("collect interval = %v, want 15m", got)
	}
	if got := cfg.GetTelemetryQueueMaxRows(); got != 5000 {
		t.Errorf("queue max rows = %d, want 5000", got)
	}
	if got := cfg.GetTelemetryQueueMaxBytes(); got != 64*1024*1024 {
		t.Errorf("queue max bytes = %d, want 64MiB", got)
	}
	if got := cfg.GetTelemetryQueueMaxAge(); got != 72*time.Hour {
		t.Errorf("queue max age = %v, want 72h", got)
	}
}

// TestPrivacySensitiveDefaultsAreOff is a privacy regression guard.
//
// Process command lines routinely carry tokens, passwords and connection
// strings passed as arguments, so capture must never become enabled by
// accident — including via a future refactor that changes how defaults work.
func TestPrivacySensitiveDefaultsAreOff(t *testing.T) {
	cfg := writeConfig(t, nil)

	if cfg.ProcessesCollectCmdline {
		t.Error("processes_collect_cmdline must default to false: command lines can contain secrets")
	}
	if cfg.CollectRoutingTable {
		t.Error("collect_routing_table must default to false: it is detailed telemetry, not basic inventory")
	}
	if cfg.IncludeBuiltinScheduledTasks {
		t.Error("include_builtin_scheduled_tasks must default to false")
	}
}

// TestTelemetryOptInIsHonoured verifies an explicit true in config.json wins
// over the struct default. This is the mechanism the whole feature-flag scheme
// relies on: Load() seeds defaults, then unmarshals the file over them.
func TestTelemetryOptInIsHonoured(t *testing.T) {
	cfg := writeConfig(t, map[string]any{
		"telemetry_enabled":          true,
		"telemetry_collect_interval": "30m",
		"processes_collect_cmdline":  true,
	})

	if !cfg.TelemetryEnabled {
		t.Error("explicit telemetry_enabled=true was not honoured")
	}
	if got := cfg.GetTelemetryCollectInterval(); got != 30*time.Minute {
		t.Errorf("collect interval = %v, want 30m", got)
	}
	if !cfg.ProcessesCollectCmdline {
		t.Error("explicit processes_collect_cmdline=true was not honoured")
	}
}

// TestTelemetryExplicitFalseIsHonoured is the complement: a key present and
// false must not be overwritten by a true default. It guards the documented
// reason for not switching these fields to *bool.
func TestTelemetryExplicitFalseIsHonoured(t *testing.T) {
	cfg := writeConfig(t, map[string]any{
		"software_sync_enabled": false,
		"telemetry_enabled":     false,
	})

	if cfg.SoftwareSyncEnabled {
		t.Error("explicit software_sync_enabled=false was overwritten by the default")
	}
	if cfg.TelemetryEnabled {
		t.Error("explicit telemetry_enabled=false was not honoured")
	}
}

// TestTelemetryGettersFloorInvalidValues ensures a zero or negative value in
// config.json cannot produce a hot loop or an unbounded queue.
func TestTelemetryGettersFloorInvalidValues(t *testing.T) {
	cfg := &Config{
		TelemetryCollectInterval: Duration(0),
		TelemetryQueueMaxRows:    -1,
		TelemetryQueueMaxBytes:   0,
		TelemetryQueueMaxAge:     Duration(-time.Hour),
	}

	if got := cfg.GetTelemetryCollectInterval(); got != 15*time.Minute {
		t.Errorf("collect interval = %v, want the 15m floor", got)
	}
	if got := cfg.GetTelemetryQueueMaxRows(); got != 5000 {
		t.Errorf("queue max rows = %d, want the 5000 floor", got)
	}
	if got := cfg.GetTelemetryQueueMaxBytes(); got != 64*1024*1024 {
		t.Errorf("queue max bytes = %d, want the 64MiB floor", got)
	}
	if got := cfg.GetTelemetryQueueMaxAge(); got != 72*time.Hour {
		t.Errorf("queue max age = %v, want the 72h floor", got)
	}
}
