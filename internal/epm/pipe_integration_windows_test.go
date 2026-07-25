//go:build windows

package epm

// End-to-end integration test for the Windows enforcement transport: a real
// Named Pipe server (PipeServer), a real client (RequestElevation) dialing
// it over an actual OS pipe, real JSON wire encoding/decoding, and a real
// EPMStore-shaped RuleProvider/AuditSink pair. Only the four OS-privileged
// identity/launch primitives (session→token resolution, hashing/Authenticode,
// and the actual elevated launch) are stubbed via the package's test seams —
// those require an interactive WTS session and SeAssignPrimaryTokenPrivilege
// that this test process is not guaranteed to hold. Everything else in the
// pipe is real.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

type staticRuleProvider struct{ rules []PolicyRule }

func (p staticRuleProvider) GetRules() ([]PolicyRule, error) { return p.rules, nil }

type recordingAuditSink struct{ entries []AuditEntry }

func (r *recordingAuditSink) InsertAuditLog(entry AuditEntry) error {
	r.entries = append(r.entries, entry)
	return nil
}

// stubIdentitySeams replaces the OS-privileged identity-resolution seams
// with deterministic fakes and restores the originals via t.Cleanup.
func stubIdentitySeams(t *testing.T, hash, userID string) {
	t.Helper()
	origSession, origToken, origUserID, origHash, origAuth :=
		sessionIDForProcessFn, queryUserTokenFn, userIDForTokenFn, computeFileHashFn, verifyAuthenticodeFn
	t.Cleanup(func() {
		sessionIDForProcessFn, queryUserTokenFn, userIDForTokenFn, computeFileHashFn, verifyAuthenticodeFn =
			origSession, origToken, origUserID, origHash, origAuth
	})

	sessionIDForProcessFn = func(_ uint32) (uint32, error) { return 1, nil }
	queryUserTokenFn = func(_ uint32) (windows.Token, error) { return windows.Token(1), nil }
	userIDForTokenFn = func(_ windows.Token) (string, error) { return userID, nil }
	computeFileHashFn = func(_ string) (string, error) { return hash, nil }
	verifyAuthenticodeFn = func(_ string) (string, error) { return "", fmt.Errorf("unsigned (stub)") }
}

// stubLaunchSeams replaces the launch seams. When shouldLaunch is false, the
// launch functions fail the test if called at all (used by the deny test to
// prove a denied request never reaches the launcher).
func stubLaunchSeams(t *testing.T, launched *bool) {
	t.Helper()
	origDup, origEnv, origLaunch := duplicateAsPrimaryTokenFn, buildEnvironmentBlockFn, launchAsUserFn
	t.Cleanup(func() {
		duplicateAsPrimaryTokenFn, buildEnvironmentBlockFn, launchAsUserFn = origDup, origEnv, origLaunch
	})

	duplicateAsPrimaryTokenFn = func(t windows.Token) (windows.Token, error) { return t, nil }
	buildEnvironmentBlockFn = func(_ windows.Token) (*environmentBlock, error) { return &environmentBlock{}, nil }
	launchAsUserFn = func(_ windows.Token, _, _ string, _ *environmentBlock) (*LaunchResult, error) {
		*launched = true
		return &LaunchResult{ProcessID: 4242}, nil
	}
}

// startTestPipeServer starts a real PipeServer in the background and stops
// it via t.Cleanup.
func startTestPipeServer(t *testing.T, provider RuleProvider, auditor *Auditor) {
	t.Helper()
	server := NewPipeServer(provider, auditor)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		server.Stop()
		cancel()
		<-done
	})
}

// requestElevationWithRetry retries RequestElevation until it succeeds or
// timeout elapses, since the server's first pipe instance takes a moment to
// be created after Serve's goroutine starts.
func requestElevationWithRetry(t *testing.T, appPath, cmdLine string, timeout time.Duration) *ElevationResult {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		result, err := RequestElevation(appPath, cmdLine)
		if err == nil {
			return result
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("RequestElevation never succeeded within %v: %v", timeout, lastErr)
	return nil
}

func TestPipeServer_EndToEnd_AllowedRequestLaunches(t *testing.T) {
	stubIdentitySeams(t, "deadbeef", "alice")
	var launched bool
	stubLaunchSeams(t, &launched)

	provider := staticRuleProvider{rules: []PolicyRule{
		{ID: "allow-hash", AppHash: "deadbeef", Decision: DecisionAllow},
	}}
	recorder := &recordingAuditSink{}
	auditor := NewAuditor(recorder)
	startTestPipeServer(t, provider, auditor)

	result := requestElevationWithRetry(t, `C:\fake\tool.exe`, "", 5*time.Second)

	if !result.Allowed {
		t.Fatalf("expected allowed, got %+v", result)
	}
	if result.ProcessID != 4242 {
		t.Errorf("ProcessID = %d, want 4242", result.ProcessID)
	}
	if !launched {
		t.Error("expected the launcher seam to have been invoked for an allowed request")
	}

	if len(recorder.entries) != 1 {
		t.Fatalf("want 1 audit entry, got %d", len(recorder.entries))
	}
	if recorder.entries[0].Decision != DecisionAllow {
		t.Errorf("audit decision = %v, want allow", recorder.entries[0].Decision)
	}
	if recorder.entries[0].UserID != "alice" {
		t.Errorf("audit UserID = %q, want alice (server-resolved, not client-supplied)", recorder.entries[0].UserID)
	}
}

func TestPipeServer_EndToEnd_DeniedRequestNeverLaunches(t *testing.T) {
	stubIdentitySeams(t, "different-hash", "bob")
	var launched bool
	stubLaunchSeams(t, &launched)

	// No rule matches "different-hash", so default-deny applies.
	provider := staticRuleProvider{rules: []PolicyRule{
		{ID: "allow-hash", AppHash: "deadbeef", Decision: DecisionAllow},
	}}
	recorder := &recordingAuditSink{}
	auditor := NewAuditor(recorder)
	startTestPipeServer(t, provider, auditor)

	result := requestElevationWithRetry(t, `C:\fake\other-tool.exe`, "", 5*time.Second)

	if result.Allowed {
		t.Fatalf("expected denied, got %+v", result)
	}
	if launched {
		t.Error("a denied request must never reach the launcher")
	}

	if len(recorder.entries) != 1 {
		t.Fatalf("want 1 audit entry, got %d", len(recorder.entries))
	}
	if recorder.entries[0].Decision != DecisionDeny {
		t.Errorf("audit decision = %v, want deny", recorder.entries[0].Decision)
	}
}
