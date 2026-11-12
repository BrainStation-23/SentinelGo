package config_test

import (
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/config"
)

func serverTestConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		Path:                   filepath.Join(t.TempDir(), "config.json"),
		SupabaseURL:            "https://example.supabase.co",
		SupabaseKey:            "test-key",
		DeviceID:               "dev",
		AuditLogsEnabled:       true,
		TaskPollingInterval:    config.Duration(5 * time.Second),
		LogFlushInterval:       config.Duration(30 * time.Second),
		UpdateInterval:         config.Duration(time.Minute),
		ServicesUpdateInterval: config.Duration(5 * time.Minute),
	}
}

const serverBlockV7 = `{"audit_logs_enabled": false, "task_polling_interval": "30s",
	"log_flush_interval": "2m0s", "software_sync_interval": "15m0s",
	"services_sync_interval": "15m0s", "version": 7, "future_key": 1}`

func TestApplyServerConfig_NewerVersionApplies(t *testing.T) {
	cfg := serverTestConfig(t)
	ch, err := cfg.ApplyServerConfig([]byte(serverBlockV7))
	if err != nil {
		t.Fatalf("ApplyServerConfig: %v", err)
	}
	if !ch.Applied || ch.Version != 7 {
		t.Fatalf("change = %+v, want applied v7", ch)
	}
	if !ch.Before.AuditLogsEnabled || ch.After.AuditLogsEnabled {
		t.Errorf("audit logs before/after = %v/%v, want true/false", ch.Before.AuditLogsEnabled, ch.After.AuditLogsEnabled)
	}
	want := map[string][2]time.Duration{
		"task_polling":  {cfg.GetTaskPollingInterval(), 30 * time.Second},
		"log_flush":     {cfg.GetLogFlushInterval(), 2 * time.Minute},
		"software_sync": {cfg.GetSoftwareInfoUpdateInterval(), 15 * time.Minute},
		"services_sync": {cfg.GetServicesUpdateInterval(), 15 * time.Minute},
	}
	for name, v := range want {
		if v[0] != v[1] {
			t.Errorf("%s = %v, want %v", name, v[0], v[1])
		}
	}
	if cfg.GetAuditLogsEnabled() {
		t.Error("GetAuditLogsEnabled() = true, want false (server turned it off)")
	}
	if !cfg.AuditLogsDisabledByServer() {
		t.Error("AuditLogsDisabledByServer() = false, want true")
	}
	if !cfg.AuditLogsEnabled {
		t.Error("local audit_logs_enabled was overwritten")
	}
}

func TestApplyServerConfig_OlderOrEqualVersionIgnored(t *testing.T) {
	cfg := serverTestConfig(t)
	if _, err := cfg.ApplyServerConfig([]byte(serverBlockV7)); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"7", "6"} {
		ch, err := cfg.ApplyServerConfig([]byte(`{"audit_logs_enabled": true, "task_polling_interval": "1h", "version": ` + v + `}`))
		if err != nil {
			t.Fatal(err)
		}
		if ch.Applied {
			t.Errorf("version %s applied over 7", v)
		}
	}
	if got := cfg.GetTaskPollingInterval(); got != 30*time.Second {
		t.Errorf("task polling = %v, want 30s from v7", got)
	}
	if cfg.ServerConfigVersion() != 7 {
		t.Errorf("version = %d, want 7", cfg.ServerConfigVersion())
	}
}

func TestApplyServerConfig_ClampsIntervals(t *testing.T) {
	cfg := serverTestConfig(t)
	ch, err := cfg.ApplyServerConfig([]byte(`{"task_polling_interval": "1s", "log_flush_interval": "1s",
		"software_sync_interval": "10s", "services_sync_interval": "48h", "version": 1}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Clamped) != 4 {
		t.Errorf("clamped = %v, want all four", ch.Clamped)
	}
	checks := []struct {
		name      string
		got, want time.Duration
	}{
		{"task_polling", cfg.GetTaskPollingInterval(), config.MinServerTaskPollingInterval},
		{"log_flush", cfg.GetLogFlushInterval(), config.MinServerLogFlushInterval},
		{"software_sync", cfg.GetSoftwareInfoUpdateInterval(), config.MinServerSyncInterval},
		{"services_sync", cfg.GetServicesUpdateInterval(), config.MaxServerInterval},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestApplyServerConfig_BadOrMissingValuesKeepLocal(t *testing.T) {
	cfg := serverTestConfig(t)
	if _, err := cfg.ApplyServerConfig([]byte(`{"task_polling_interval": "soon", "log_flush_interval": "-5m", "version": 2}`)); err != nil {
		t.Fatal(err)
	}
	if got := cfg.GetTaskPollingInterval(); got != 5*time.Second {
		t.Errorf("task polling = %v, want local 5s", got)
	}
	if got := cfg.GetLogFlushInterval(); got != 30*time.Second {
		t.Errorf("log flush = %v, want local 30s", got)
	}
	if !cfg.GetAuditLogsEnabled() {
		t.Error("audit logs off although the server sent no switch")
	}
	if _, err := cfg.ApplyServerConfig([]byte(`not json`)); err == nil {
		t.Error("ApplyServerConfig(not json) = nil error")
	}
}

func TestApplyServerConfig_LocalKillSwitchWins(t *testing.T) {
	cfg := serverTestConfig(t)
	cfg.AuditLogsEnabled = false
	if _, err := cfg.ApplyServerConfig([]byte(`{"audit_logs_enabled": true, "version": 3}`)); err != nil {
		t.Fatal(err)
	}
	if cfg.GetAuditLogsEnabled() {
		t.Error("server turned audit logs on over a local audit_logs_enabled: false")
	}
	if cfg.AuditLogsDisabledByServer() {
		t.Error("AuditLogsDisabledByServer() = true; the local switch is what keeps it off")
	}
}

func TestApplyServerConfig_PersistsAcrossRestart(t *testing.T) {
	cfg := serverTestConfig(t)
	if _, err := cfg.ApplyServerConfig([]byte(serverBlockV7)); err != nil {
		t.Fatal(err)
	}
	if err := cfg.SaveAtomic(); err != nil {
		t.Fatalf("SaveAtomic: %v", err)
	}
	loaded, err := config.Load(cfg.Path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.ServerConfigVersion() != 7 {
		t.Errorf("reloaded version = %d, want 7", loaded.ServerConfigVersion())
	}
	if loaded.GetAuditLogsEnabled() {
		t.Error("reloaded config has audit logs on")
	}
	if !loaded.AuditLogsEnabled {
		t.Error("reloaded local audit_logs_enabled = false, want true (untouched)")
	}
	if got := loaded.GetTaskPollingInterval(); got != 30*time.Second {
		t.Errorf("reloaded task polling = %v, want 30s", got)
	}
	if got := time.Duration(loaded.TaskPollingInterval); got != 5*time.Second {
		t.Errorf("reloaded local task_polling_interval = %v, want 5s (untouched)", got)
	}
}

// TestApplyServerConfig_ConcurrentWithSave runs applies, saves and reads at
// once; run with -race.
func TestApplyServerConfig_ConcurrentWithSave(t *testing.T) {
	cfg := serverTestConfig(t)
	var wg sync.WaitGroup
	for i := 1; i <= 20; i++ {
		wg.Add(3)
		go func(v int) {
			defer wg.Done()
			_, _ = cfg.ApplyServerConfig([]byte(`{"task_polling_interval": "30s", "version": ` + strconv.Itoa(v) + `}`))
		}(i)
		go func() { defer wg.Done(); _ = cfg.SaveAtomic() }()
		go func() { defer wg.Done(); _ = cfg.GetTaskPollingInterval() }()
	}
	wg.Wait()
	if cfg.ServerConfigVersion() != 20 {
		t.Errorf("version = %d, want the highest, 20", cfg.ServerConfigVersion())
	}
}
