package internal

import (
	"encoding/json"
	"log"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/remoteconfig"
	"sentinelgo/internal/sanitize"
)

// Server-side agent settings (#466, sentinel-ops#902): agent_get_tasks and the
// agent_enqueue_* replies carry a "config" block. A block newer than the one
// applied is clamped, applied, persisted in config.json (server_config) and
// then the running components follow it:
//   - audit_logs_enabled: the audit-log pipeline stops (queue dropped,
//     checkpoints kept) or starts again from its checkpoints. A local
//     audit_logs_enabled: false stays off whatever the server says.
//   - task_polling_interval, log_flush_interval: the task loop and the log
//     collection loop reset their tickers.
//   - software_sync_interval, services_sync_interval: the scheduler resets
//     the software-sync and services-collect tickers.

// watchServerConfig registers the handler for server config blocks.
func (mi *MainIntegration) watchServerConfig() {
	remoteconfig.SetHandler(mi.applyServerConfig)
}

// unwatchServerConfig unregisters it and waits for running reconciles.
func (mi *MainIntegration) unwatchServerConfig() {
	remoteconfig.SetHandler(nil)
	mi.serverCfgWG.Wait()
}

// applyServerConfig is the remoteconfig handler. It runs on the goroutine of
// whatever RPC brought the block, which can be the audit-log upload loop
// itself, so the components are reconciled on a goroutine of their own (the
// pipeline can't be stopped from inside its own loop).
func (mi *MainIntegration) applyServerConfig(raw json.RawMessage) {
	ch, err := mi.cfg.ApplyServerConfig(raw)
	if err != nil {
		log.Printf("Server config ignored: %v", sanitize.ForLog(err.Error()))
		return
	}
	if !ch.Applied {
		return
	}
	logServerConfigChange(ch)
	if err := mi.cfg.SaveAtomic(); err != nil {
		log.Printf("Warning: server config v%d applied but not saved: %v", ch.Version, err)
	}
	mi.serverCfgWG.Add(1)
	go func() {
		defer mi.serverCfgWG.Done()
		mi.reconcileServerConfig(ch)
	}()
}

// logServerConfigChange logs one line per value the block changed.
func logServerConfigChange(ch config.ServerConfigChange) {
	b, a := ch.Before, ch.After
	log.Printf("Server config v%d applied", ch.Version)
	for _, name := range ch.Clamped {
		log.Printf("Server config: %s out of range, clamped", name)
	}
	if b.AuditLogsEnabled != a.AuditLogsEnabled {
		log.Printf("Server config: audit logs %s", map[bool]string{true: "enabled", false: "disabled"}[a.AuditLogsEnabled])
	}
	for _, d := range []struct {
		name          string
		before, after any
	}{
		{"task_polling_interval", b.TaskPollingInterval, a.TaskPollingInterval},
		{"log_flush_interval", b.LogFlushInterval, a.LogFlushInterval},
		{"software_sync_interval", b.SoftwareSyncInterval, a.SoftwareSyncInterval},
		{"services_sync_interval", b.ServicesSyncInterval, a.ServicesSyncInterval},
	} {
		if d.before != d.after {
			log.Printf("Server config: %s %v -> %v", d.name, d.before, d.after)
		}
	}
}

// reconcileServerConfig brings the running components in line with the
// effective config. It reads the current state rather than ch, so
// reconciles that overlap or run out of order still end right.
func (mi *MainIntegration) reconcileServerConfig(ch config.ServerConfigChange) {
	mi.reconcileAuditLogs()

	if mi.taskManager != nil {
		mi.taskManager.Reschedule()
	}
	eff := mi.cfg.Effective()
	if ch.Before.SoftwareSyncInterval != ch.After.SoftwareSyncInterval {
		mi.setTaskInterval("software-sync", eff.SoftwareSyncInterval)
	}
	if ch.Before.ServicesSyncInterval != ch.After.ServicesSyncInterval {
		mi.setTaskInterval("services-collect", eff.ServicesSyncInterval)
	}
}

// setTaskInterval retimes a scheduler task; a task that isn't registered
// (e.g. services-collect when its store failed to open) is skipped.
func (mi *MainIntegration) setTaskInterval(name string, d time.Duration) {
	if mi.scheduler == nil {
		return
	}
	if err := mi.scheduler.SetInterval(name, d); err != nil {
		log.Printf("Server config: %s not retimed: %v", name, err)
	}
}

// reconcileAuditLogs stops or starts the audit-log pipeline to match the
// effective audit_logs_enabled, and retimes it when it keeps running.
func (mi *MainIntegration) reconcileAuditLogs() {
	mi.loggingMu.Lock()
	defer mi.loggingMu.Unlock()
	if mi.loggingStopped {
		return
	}

	want := mi.cfg.GetAuditLogsEnabled()
	switch {
	case !want && mi.loggingService != nil:
		if mi.cfg.AuditLogsDisabledByServer() {
			log.Printf("Audit logs disabled by server; stopping collection and dropping the upload queue")
		}
		if err := mi.loggingService.Discard(); err != nil {
			log.Printf("Warning: audit log queue not fully dropped: %v", err)
		}
		mi.loggingService = nil
	case want && mi.loggingService == nil && mi.runCtx != nil:
		log.Printf("Audit logs enabled by server; resuming collection from the checkpoints")
		if err := mi.startLoggingServiceLocked(mi.runCtx); err != nil {
			log.Printf("Warning: audit log service not restarted: %v", err)
		}
	case mi.loggingService != nil:
		mi.loggingService.Reschedule()
	}
}
