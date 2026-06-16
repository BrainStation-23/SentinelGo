package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"sentinelgo/internal/auditlogs/collector"
	"sentinelgo/internal/auditlogs/parser"
	"sentinelgo/internal/config"
	"sentinelgo/internal/models"
	"sentinelgo/internal/osinfo"
	"sentinelgo/internal/osinfo/shared"
	servicessvc "sentinelgo/internal/service/services"
	swsvc "sentinelgo/internal/service/software"
)

// maxDebugAuditEntries caps how many audit log entries the debug dump prints.
// An empty checkpoint makes the collector read full channel history (there is
// no time-window filter — the checkpoint is the only "what's new" boundary),
// which on a busy host can be enormous. The persisted queue is viewable via
// -logging-stats.
const maxDebugAuditEntries = 500

// debugDump is the combined snapshot printed by -debug-dump. It mirrors exactly
// what the agent collects (and would send), without uploading or persisting.
type debugDump struct {
	CollectedAt string               `json:"collected_at"`
	OSInfo      *shared.SystemInfo   `json:"osinfo"`
	Software    []swsvc.SoftwareInfo `json:"software"`
	Services    []models.ServiceInfo `json:"services"`
	AuditLogs   []models.AuditLog    `json:"auditlogs"`
}

// loadConfigBestEffort loads the config but never fails: a debug dump must work
// even on a half-broken install. Returns nil if the config can't be loaded.
func loadConfigBestEffort() *config.Config {
	cfg, err := config.Load("")
	if err != nil {
		log.Printf("Warning: Could not load config (audit-log labels will be empty): %v", err)
		return nil
	}
	return cfg
}

// redactSensitiveDebugFields returns a copy of known debug payloads with
// sensitive fields redacted before printing.
func redactSensitiveDebugFields(v any) any {
	const redacted = "[REDACTED]"

	switch t := v.(type) {
	case *shared.SystemInfo:
		if t == nil {
			return v
		}
		c := *t
		c.SecurityInfo.IdentityAccessControl.SSHPasswordAuth = redacted
		c.SecurityInfo.NetworkExposureAccess.SSHPasswordAuthStatus = redacted
		return &c
	case debugDump:
		c := t
		if c.OSInfo != nil {
			osCopy := *c.OSInfo
			osCopy.SecurityInfo.IdentityAccessControl.SSHPasswordAuth = redacted
			osCopy.SecurityInfo.NetworkExposureAccess.SSHPasswordAuthStatus = redacted
			c.OSInfo = &osCopy
		}
		return c
	default:
		return v
	}
}

// printJSON marshals v as indented JSON to stdout.
func printJSON(v any) {
	safe := redactSensitiveDebugFields(v)
	data, err := json.MarshalIndent(safe, "", "  ")
	if err != nil {
		log.Printf("Error marshaling to JSON: %v", err)
		return
	}
	fmt.Println(string(data))
}

// collectAuditLogsLive runs a fresh audit-log collection and parse WITHOUT
// touching the SQLite queue or advancing the persisted checkpoint. It uses a
// throwaway empty checkpoint and caps the result at maxDebugAuditEntries.
func collectAuditLogsLive(ctx context.Context, cfg *config.Config) []models.AuditLog {
	pc := parser.ParserConfig{OSType: runtime.GOOS}
	if cfg != nil {
		pc.AgentID = cfg.AgentID
		pc.DeviceID = cfg.DeviceID
		pc.AgentVersion = cfg.CurrentVersion
	}

	c := collector.NewCollector()
	entries, _, err := c.Collect(ctx, collector.CheckpointData{})
	if err != nil {
		log.Printf("Warning: audit log collection error: %v", err)
	}

	parsed := parser.NewParser().Parse(entries, pc)
	if len(parsed) > maxDebugAuditEntries {
		fmt.Fprintf(os.Stderr, "Note: audit log output truncated to %d of %d entries; use -logging-stats for the persisted queue\n", maxDebugAuditEntries, len(parsed))
		parsed = parsed[:maxDebugAuditEntries]
	}
	return parsed
}

// HandleDebugDump runs every collector live and prints one combined JSON
// document. It sends nothing to the backend and writes nothing to disk. It
// calls the collectors directly, so it works even when software/audit-log
// sending is disabled in config — the point is to see the data regardless.
func HandleDebugDump() {
	cfg := loadConfigBestEffort()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dump := debugDump{
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
		OSInfo:      osinfo.Collect(),
		Software:    swsvc.NewSoftwareService().GetSoftwareList(),
		Services:    servicessvc.NewServicesService().GetServiceList(),
		AuditLogs:   collectAuditLogsLive(ctx, cfg),
	}
	printJSON(dump)
}

// HandleOSInfoDump collects OS info and prints it as JSON. No upload.
func HandleOSInfoDump() {
	printJSON(osinfo.Collect())
}

// HandleAuditLogsDump collects audit logs live and prints them as JSON,
// without persisting them or advancing the checkpoint.
func HandleAuditLogsDump() {
	cfg := loadConfigBestEffort()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	printJSON(collectAuditLogsLive(ctx, cfg))
}
