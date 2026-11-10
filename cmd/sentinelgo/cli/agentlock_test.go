package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sentinelgo/internal/lockfile"
)

// TestMain points the agent lock at a temporary file, so the handler tests
// don't need the real lock directory (root-owned on an installed host).
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sentinelgo-cli-lock")
	if err != nil {
		panic(err)
	}
	newAgentLock = func() *lockfile.LockFile {
		return lockfile.NewLockFileWithPath(filepath.Join(dir, lockfile.AgentLockName+".lock"))
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// While the agent holds its lock, the CLI log commands refuse instead of
// running a second pipeline on the same queue (#436).
func TestLogCommands_RefuseWhileAgentRuns(t *testing.T) {
	held := newAgentLock()
	if err := held.TryAcquire(); err != nil {
		t.Fatalf("hold the agent lock: %v", err)
	}
	defer func() { _ = held.Release() }()

	for name, run := range map[string]func(){
		"collect-logs":   HandleCollectLogs,
		"upload-logs":    HandleUploadLogs,
		"logging-stats":  HandleLoggingStats,
		"run-audit-logs": func() { HandleAuditLogsStandalone(tempLoggingConfig(t)) },
	} {
		t.Run(name, func(t *testing.T) {
			codes := recordExit(t)
			stubDefaultConfig(t, tempLoggingConfig(t), nil)

			out := captureStdout(run)

			wantExit(t, codes, 1)
			if !strings.Contains(out, "agent is running") {
				t.Errorf("missing refusal; got %q", out)
			}
			for _, s := range []string{"completed", "Logging Statistics", "is running. Press"} {
				if strings.Contains(out, s) {
					t.Errorf("the command ran (%q) although the agent holds the lock; got %q", s, out)
				}
			}
		})
	}
}
