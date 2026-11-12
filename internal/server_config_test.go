package internal

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/remoteconfig"
	"sentinelgo/internal/scheduler"
	authsvc "sentinelgo/internal/service/auth"
)

func serverConfigIntegration(t *testing.T) (*MainIntegration, *config.Config) {
	t.Helper()
	cfg := startTestConfig(t, "http://127.0.0.1:1")
	cfg.AuditLogsEnabled = true
	sched := scheduler.NewScheduler()
	noop := func(context.Context, *config.Config, *authsvc.Service) error { return nil }
	for _, name := range []string{"software-sync", "services-collect"} {
		if err := sched.AddTask(&scheduler.Task{Name: name, Interval: time.Minute, Enabled: true, Handler: noop}); err != nil {
			t.Fatal(err)
		}
	}
	mi := NewMainIntegrationWith(cfg, sched)
	mi.runCtx = context.Background()
	mi.watchServerConfig()
	t.Cleanup(mi.unwatchServerConfig)
	return mi, cfg
}

// TestServerConfig_AppliedPersistedAndRetimed: a block from an RPC reply is
// applied, saved to config.json and retimes the scheduler tasks; an older
// block is ignored (#466).
func TestServerConfig_AppliedPersistedAndRetimed(t *testing.T) {
	mi, cfg := serverConfigIntegration(t)

	remoteconfig.Observe(json.RawMessage(`{"audit_logs_enabled": false, "task_polling_interval": "30s",
		"log_flush_interval": "2m0s", "software_sync_interval": "15m0s",
		"services_sync_interval": "20m0s", "version": 7}`))
	mi.serverCfgWG.Wait()

	if cfg.GetAuditLogsEnabled() {
		t.Error("audit logs still enabled")
	}
	mi.loggingMu.Lock()
	running := mi.loggingService != nil
	mi.loggingMu.Unlock()
	if running {
		t.Error("audit log service running while disabled by server")
	}
	status := mi.scheduler.GetTaskStatus()
	if got := status["software-sync"].Interval; got != 15*time.Minute {
		t.Errorf("software-sync interval = %v, want 15m", got)
	}
	if got := status["services-collect"].Interval; got != 20*time.Minute {
		t.Errorf("services-collect interval = %v, want 20m", got)
	}

	saved, err := config.Load(cfg.Path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if saved.ServerConfigVersion() != 7 || saved.GetAuditLogsEnabled() {
		t.Errorf("saved config: version %d, audit logs %v; want 7, false", saved.ServerConfigVersion(), saved.GetAuditLogsEnabled())
	}

	remoteconfig.Observe(json.RawMessage(`{"software_sync_interval": "1h", "version": 6}`))
	mi.serverCfgWG.Wait()
	if got := mi.scheduler.GetTaskStatus()["software-sync"].Interval; got != 15*time.Minute {
		t.Errorf("older block applied: software-sync interval = %v", got)
	}
}

// TestServerConfig_IgnoredAfterStop: once Stop unregisters the handler, a
// late reply changes nothing.
func TestServerConfig_IgnoredAfterStop(t *testing.T) {
	mi, cfg := serverConfigIntegration(t)
	mi.unwatchServerConfig()

	remoteconfig.Observe(json.RawMessage(`{"audit_logs_enabled": false, "version": 1}`))
	if cfg.ServerConfigVersion() != 0 || !cfg.GetAuditLogsEnabled() {
		t.Error("server config applied after the handler was unregistered")
	}
}
