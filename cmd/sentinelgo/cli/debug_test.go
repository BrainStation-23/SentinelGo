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

// ── debugDump JSON shape ─────────────────────────────────────────────────────

// The dump is marshaled directly (not via captureStdout): a full SystemInfo
// serializes to more than the OS pipe buffer, and captureStdout only drains
// after fn returns, so routing it through stdout capture would deadlock. The
// actual stdout printing is exercised by running the binary.
func TestDebugDump_marshalsValidJSON(t *testing.T) {
	dump := debugDump{
		CollectedAt: "2026-06-16T00:00:00Z",
		OSInfo:      &shared.SystemInfo{Hostname: "test-host"},
		Software:    []swsvc.SoftwareInfo{{Name: "curl", Source: "deb_packages"}},
		Services:    []models.ServiceInfo{{Name: "sshd", Source: "systemd"}},
		AuditLogs:   nil,
	}

	data, err := json.MarshalIndent(dump, "", "  ")
	if err != nil {
		t.Fatalf("debugDump did not marshal: %v", err)
	}

	var decoded debugDump
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("debugDump produced invalid JSON: %v", err)
	}
	if decoded.OSInfo == nil || decoded.OSInfo.Hostname != "test-host" {
		t.Errorf("osinfo did not round-trip; got %+v", decoded.OSInfo)
	}
	if len(decoded.Software) != 1 || decoded.Software[0].Name != "curl" {
		t.Errorf("software did not round-trip; got %+v", decoded.Software)
	}
	for _, key := range []string{`"collected_at"`, `"osinfo"`, `"software"`, `"services"`, `"auditlogs"`} {
		if !strings.Contains(string(data), key) {
			t.Errorf("output missing %s field", key)
		}
	}
}

// ── collectAuditLogsLive ─────────────────────────────────────────────────────

// A cancelled context makes the collector return promptly. We only assert it
// doesn't panic and the result is capped — audit log content is environment-
// and OS-dependent.
func TestCollectAuditLogsLive_cancelledContext_noPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	logs := collectAuditLogsLive(ctx, nil)
	if len(logs) > maxDebugAuditEntries {
		t.Errorf("result not capped: got %d, cap %d", len(logs), maxDebugAuditEntries)
	}
}
