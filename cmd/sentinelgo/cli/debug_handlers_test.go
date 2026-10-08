package cli

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/auditlogs/collector"
	"sentinelgo/internal/config"
	"sentinelgo/internal/models"
	"sentinelgo/internal/osinfo/shared"
	swsvc "sentinelgo/internal/service/software"
)

// ── test doubles for the debug-dump seams ────────────────────────────────────

// fakeAuditCollector is a canned collector.Collector: Collect returns the
// configured entries/error and never touches the host's logs.
type fakeAuditCollector struct {
	entries []collector.RawLogEntry
	err     error
}

func (f *fakeAuditCollector) Collect(_ context.Context, cp collector.CheckpointData) ([]collector.RawLogEntry, collector.CheckpointData, error) {
	return f.entries, cp, f.err
}

func (f *fakeAuditCollector) Subscribe(_ context.Context, _ chan<- collector.RawLogEntry) error {
	return nil
}

func (f *fakeAuditCollector) Sources() []string { return []string{"fake"} }

// stubDebugCollectors replaces every host collector the debug handlers use
// with canned data, restoring the originals when the test ends.
func stubDebugCollectors(t *testing.T, sys *shared.SystemInfo, audit *fakeAuditCollector) {
	t.Helper()
	oldOS, oldSW, oldSvc, oldAudit := collectOSInfo, collectSoftware, collectServices, newAuditCollector
	t.Cleanup(func() {
		collectOSInfo, collectSoftware, collectServices, newAuditCollector = oldOS, oldSW, oldSvc, oldAudit
	})
	collectOSInfo = func() *shared.SystemInfo { return sys }
	collectSoftware = func() []swsvc.SoftwareInfo {
		return []swsvc.SoftwareInfo{{Name: "curl", Source: "deb_packages"}}
	}
	collectServices = func() []models.ServiceInfo {
		return []models.ServiceInfo{{Name: "sshd", Source: "systemd"}}
	}
	newAuditCollector = func() collector.Collector { return audit }
}

// stubDefaultConfig makes loadDefaultConfig return cfg/err instead of reading
// (and creating) the real system config path.
func stubDefaultConfig(t *testing.T, cfg *config.Config, err error) {
	t.Helper()
	old := loadDefaultConfig
	t.Cleanup(func() { loadDefaultConfig = old })
	loadDefaultConfig = func() (*config.Config, error) { return cfg, err }
}

func sysInfoWithSSHSecrets() *shared.SystemInfo {
	s := &shared.SystemInfo{Hostname: "test-host"}
	s.SecurityInfo.IdentityAccessControl.SSHPasswordAuth = "Enabled"
	s.SecurityInfo.NetworkExposureAccess.SSHPasswordAuthStatus = "Enabled"
	return s
}

// ── loadConfigBestEffort ─────────────────────────────────────────────────────

func TestLoadConfigBestEffort(t *testing.T) {
	want := &config.Config{DeviceID: "dev-1"}
	stubDefaultConfig(t, want, nil)
	if got := loadConfigBestEffort(); got != want {
		t.Errorf("loadConfigBestEffort() = %p, want %p", got, want)
	}

	stubDefaultConfig(t, nil, errors.New("unreadable"))
	if got := loadConfigBestEffort(); got != nil {
		t.Errorf("loadConfigBestEffort() on error = %+v, want nil", got)
	}
}

// ── redactSensitiveDebugFields ───────────────────────────────────────────────

func TestRedactSensitiveDebugFields_SystemInfo(t *testing.T) {
	orig := sysInfoWithSSHSecrets()

	got, ok := redactSensitiveDebugFields(orig).(*shared.SystemInfo)
	if !ok {
		t.Fatalf("redacted value has type %T, want *shared.SystemInfo", got)
	}
	if got.SecurityInfo.IdentityAccessControl.SSHPasswordAuth != "[REDACTED]" ||
		got.SecurityInfo.NetworkExposureAccess.SSHPasswordAuthStatus != "[REDACTED]" {
		t.Errorf("SSH fields not redacted: %+v", got.SecurityInfo)
	}
	if got.Hostname != "test-host" {
		t.Errorf("non-sensitive field changed: hostname %q", got.Hostname)
	}
	// The caller's value must not be mutated.
	if orig.SecurityInfo.IdentityAccessControl.SSHPasswordAuth != "Enabled" ||
		orig.SecurityInfo.NetworkExposureAccess.SSHPasswordAuthStatus != "Enabled" {
		t.Errorf("redaction mutated the original: %+v", orig.SecurityInfo)
	}
}

func TestRedactSensitiveDebugFields_NilSystemInfo(t *testing.T) {
	var nilInfo *shared.SystemInfo
	got, ok := redactSensitiveDebugFields(nilInfo).(*shared.SystemInfo)
	if !ok || got != nil {
		t.Errorf("nil *SystemInfo should pass through unchanged; got %#v", got)
	}
}

func TestRedactSensitiveDebugFields_DebugDump(t *testing.T) {
	orig := sysInfoWithSSHSecrets()
	got, ok := redactSensitiveDebugFields(debugDump{OSInfo: orig}).(debugDump)
	if !ok {
		t.Fatalf("redacted value has wrong type %T", got)
	}
	if got.OSInfo == orig {
		t.Fatal("redacted dump shares the original OSInfo pointer")
	}
	if got.OSInfo.SecurityInfo.IdentityAccessControl.SSHPasswordAuth != "[REDACTED]" ||
		got.OSInfo.SecurityInfo.NetworkExposureAccess.SSHPasswordAuthStatus != "[REDACTED]" {
		t.Errorf("SSH fields not redacted: %+v", got.OSInfo.SecurityInfo)
	}
	if orig.SecurityInfo.IdentityAccessControl.SSHPasswordAuth != "Enabled" {
		t.Error("redaction mutated the original OSInfo")
	}

	// A dump without OS info passes through.
	empty, ok := redactSensitiveDebugFields(debugDump{CollectedAt: "now"}).(debugDump)
	if !ok || empty.OSInfo != nil || empty.CollectedAt != "now" {
		t.Errorf("dump without OSInfo altered: %+v", empty)
	}
}

func TestRedactSensitiveDebugFields_OtherTypesUnchanged(t *testing.T) {
	in := []string{"a", "b"}
	got, ok := redactSensitiveDebugFields(in).([]string)
	if !ok || len(got) != 2 || got[0] != "a" {
		t.Errorf("unknown type altered: %#v", got)
	}
}

// ── printJSON ────────────────────────────────────────────────────────────────

func TestPrintJSON_RedactsAndPrints(t *testing.T) {
	out := captureStdout(func() { printJSON(sysInfoWithSSHSecrets()) })

	var decoded shared.SystemInfo
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("printJSON produced invalid JSON: %v\n%s", err, out)
	}
	if decoded.Hostname != "test-host" {
		t.Errorf("hostname = %q", decoded.Hostname)
	}
	if strings.Contains(out, `"Enabled"`) {
		t.Errorf("unredacted SSH value printed:\n%s", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("redaction marker missing:\n%s", out)
	}
}

func TestPrintJSON_MarshalErrorPrintsNothing(t *testing.T) {
	out := captureStdout(func() { printJSON(make(chan int)) })
	if out != "" {
		t.Errorf("expected no stdout on marshal error, got %q", out)
	}
}

// ── collectAuditLogsLive (with a fake collector) ─────────────────────────────

func TestCollectAuditLogsLive_LabelsFromConfig(t *testing.T) {
	stubDebugCollectors(t, nil, &fakeAuditCollector{entries: []collector.RawLogEntry{
		{Timestamp: time.Unix(0, 0), Source: "journal", Severity: "err", RawMessage: "x"},
	}})
	cfg := &config.Config{AgentID: "agent-1", DeviceID: "dev-1", CurrentVersion: "v9"}

	logs := collectAuditLogsLive(context.Background(), cfg)
	if len(logs) != 1 {
		t.Fatalf("got %d logs, want 1", len(logs))
	}
	if logs[0].AgentID != "agent-1" || logs[0].DeviceID != "dev-1" || logs[0].AgentVersion != "v9" {
		t.Errorf("config labels not applied: %+v", logs[0])
	}
}

func TestCollectAuditLogsLive_TruncatesToCap(t *testing.T) {
	entries := make([]collector.RawLogEntry, maxDebugAuditEntries+7)
	for i := range entries {
		entries[i] = collector.RawLogEntry{Source: "journal", RawMessage: "m"}
	}
	stubDebugCollectors(t, nil, &fakeAuditCollector{entries: entries})

	if logs := collectAuditLogsLive(context.Background(), nil); len(logs) != maxDebugAuditEntries {
		t.Errorf("got %d logs, want cap %d", len(logs), maxDebugAuditEntries)
	}
}

// A collector error is logged, and whatever entries came back are still parsed.
func TestCollectAuditLogsLive_CollectorErrorKeepsPartialEntries(t *testing.T) {
	stubDebugCollectors(t, nil, &fakeAuditCollector{
		entries: []collector.RawLogEntry{{Source: "journal", RawMessage: "partial"}},
		err:     errors.New("permission denied"),
	})

	if logs := collectAuditLogsLive(context.Background(), nil); len(logs) != 1 {
		t.Errorf("got %d logs, want the 1 partial entry", len(logs))
	}
}

// ── HandleDebugDump / HandleOSInfoDump / HandleAuditLogsDump ─────────────────

func TestHandleDebugDump_PrintsCombinedRedactedJSON(t *testing.T) {
	stubDefaultConfig(t, &config.Config{AgentID: "agent-1", DeviceID: "dev-1"}, nil)
	stubDebugCollectors(t, sysInfoWithSSHSecrets(), &fakeAuditCollector{entries: []collector.RawLogEntry{
		{Source: "journal", RawMessage: "login"},
	}})

	out := captureStdout(HandleDebugDump)

	var decoded debugDump
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("HandleDebugDump produced invalid JSON: %v\n%s", err, out)
	}
	if decoded.CollectedAt == "" {
		t.Error("collected_at is empty")
	}
	if decoded.OSInfo == nil || decoded.OSInfo.Hostname != "test-host" {
		t.Fatalf("osinfo = %+v", decoded.OSInfo)
	}
	if decoded.OSInfo.SecurityInfo.IdentityAccessControl.SSHPasswordAuth != "[REDACTED]" {
		t.Error("ssh_password_auth not redacted in the dump")
	}
	if len(decoded.Software) != 1 || len(decoded.Services) != 1 {
		t.Errorf("software/services = %d/%d, want 1/1", len(decoded.Software), len(decoded.Services))
	}
	if len(decoded.AuditLogs) != 1 || decoded.AuditLogs[0].DeviceID != "dev-1" {
		t.Errorf("auditlogs = %+v", decoded.AuditLogs)
	}
}

// A broken config must not stop the dump; audit logs just lose their labels.
func TestHandleDebugDump_WorksWithoutConfig(t *testing.T) {
	stubDefaultConfig(t, nil, errors.New("no config"))
	stubDebugCollectors(t, &shared.SystemInfo{Hostname: "h"}, &fakeAuditCollector{entries: []collector.RawLogEntry{
		{Source: "journal", RawMessage: "login"},
	}})

	var decoded debugDump
	out := captureStdout(HandleDebugDump)
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(decoded.AuditLogs) != 1 || decoded.AuditLogs[0].DeviceID != "" {
		t.Errorf("auditlogs = %+v, want one unlabeled entry", decoded.AuditLogs)
	}
}

func TestHandleOSInfoDump(t *testing.T) {
	stubDebugCollectors(t, sysInfoWithSSHSecrets(), &fakeAuditCollector{})

	out := captureStdout(HandleOSInfoDump)
	var decoded shared.SystemInfo
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if decoded.Hostname != "test-host" {
		t.Errorf("hostname = %q", decoded.Hostname)
	}
	if decoded.SecurityInfo.NetworkExposureAccess.SSHPasswordAuthStatus != "[REDACTED]" {
		t.Error("ssh_password_auth_status not redacted")
	}
}

func TestHandleAuditLogsDump(t *testing.T) {
	stubDefaultConfig(t, &config.Config{AgentID: "agent-1"}, nil)
	stubDebugCollectors(t, nil, &fakeAuditCollector{entries: []collector.RawLogEntry{
		{Source: "journal", RawMessage: "a"},
		{Source: "journal", RawMessage: "b"},
	}})

	out := captureStdout(HandleAuditLogsDump)
	var decoded []models.AuditLog
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(decoded) != 2 || decoded[0].AgentID != "agent-1" {
		t.Errorf("audit logs = %+v", decoded)
	}
}
