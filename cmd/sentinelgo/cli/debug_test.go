package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"sentinelgo/internal/models"
	"sentinelgo/internal/osinfo/shared"
	swsvc "sentinelgo/internal/service/software"
)

// ── printJSON ────────────────────────────────────────────────────────────────

func TestPrintJSON_validDebugDump(t *testing.T) {
	dump := debugDump{
		CollectedAt: "2026-06-16T00:00:00Z",
		OSInfo:      &shared.SystemInfo{Hostname: "test-host"},
		Software:    []swsvc.SoftwareInfo{{Name: "curl", Source: "deb_packages"}},
		Services:    []models.ServiceInfo{{Name: "sshd", Source: "systemd"}},
		AuditLogs:   nil,
	}

	out := captureStdout(func() { printJSON(dump) })

	var decoded debugDump
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("printJSON produced invalid JSON: %v\nOutput: %q", err, out)
	}
	if decoded.OSInfo == nil || decoded.OSInfo.Hostname != "test-host" {
		t.Errorf("osinfo did not round-trip; got %+v", decoded.OSInfo)
	}
	if !strings.Contains(out, "\"collected_at\"") {
		t.Errorf("output missing collected_at field; got %q", out)
	}
}

// ── collectAuditLogsLive ─────────────────────────────────────────────────────

// A cancelled context makes the collector return promptly. We only assert it
// doesn't panic and returns a (possibly empty) slice — audit log content is
// environment- and OS-dependent.
func TestCollectAuditLogsLive_cancelledContext_noPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	logs := collectAuditLogsLive(ctx, nil)
	if logs == nil {
		// Parse returns a non-nil empty slice; nil would be unexpected but not fatal.
		t.Log("collectAuditLogsLive returned nil slice (acceptable)")
	}
	if len(logs) > maxDebugAuditEntries {
		t.Errorf("result not capped: got %d, cap %d", len(logs), maxDebugAuditEntries)
	}
}
