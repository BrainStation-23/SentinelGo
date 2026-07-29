package epm

// server_test.go drives the ONE shared implementation of evaluate-hash-
// verify-launch-audit (server.go's Server.elevate) end to end over a real
// net.Pipe() connection, with fake Transport/Launcher/Identifier standing in
// for the platform specifics. Because server.go carries no build tag, this
// is the same code every one of the three real platform transports calls —
// so unlike the old triplicated pipe_windows.go/socket_linux.go/
// socket_darwin.go (only ever integration-tested on Windows, via
// pipe_integration_windows_test.go), this test exercises the shared logic on
// every CI platform, including the two that previously had none at all.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"
)

// testAppPath is an absolute path valid on whichever GOOS the test actually
// runs on — validateAppPath (server.go) uses filepath.IsAbs, which requires a
// volume/drive letter on Windows, so a bare "/opt/tool" (valid on
// linux/darwin) would fail there. This is what a real request's AppPath
// always is: something the OS itself considers absolute.
func testAppPath() string {
	if runtime.GOOS == "windows" {
		return `C:\apps\tool.exe`
	}
	return "/opt/tool"
}

// pipeConn adapts a net.Conn (one end of net.Pipe()) to the Conn interface,
// using the same newline-delimited-JSON framing as the real Unix transports
// (transport_unix.go's unixConn) — reimplemented locally, untagged, so this
// test runs on every GOOS rather than only linux/darwin.
type pipeConn struct {
	conn net.Conn
	peer PeerIdentity
	dec  *json.Decoder
}

func newPipeConn(conn net.Conn, peer PeerIdentity) *pipeConn {
	return &pipeConn{conn: conn, peer: peer, dec: json.NewDecoder(conn)}
}

func (c *pipeConn) Peer() PeerIdentity { return c.peer }
func (c *pipeConn) ReadMessage() ([]byte, error) {
	var raw json.RawMessage
	if err := c.dec.Decode(&raw); err != nil {
		return nil, err
	}
	return raw, nil
}
func (c *pipeConn) WriteMessage(msg []byte) error {
	_, err := c.conn.Write(append(msg, '\n'))
	return err
}
func (c *pipeConn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }
func (c *pipeConn) Close() error                  { return c.conn.Close() }

// memTransport hands back pre-built Conns from a channel, one per Accept —
// the test constructs a net.Pipe() pair per simulated "connection" and feeds
// the server-side half in.
type memTransport struct {
	conns  chan Conn
	closed chan struct{}
}

func newMemTransport() *memTransport {
	return &memTransport{conns: make(chan Conn, 8), closed: make(chan struct{})}
}

func (t *memTransport) Listen(context.Context) error { return nil }
func (t *memTransport) Accept(ctx context.Context) (Conn, error) {
	select {
	case c, ok := <-t.conns:
		if !ok {
			return nil, fmt.Errorf("transport closed")
		}
		return c, nil
	case <-t.closed:
		return nil, fmt.Errorf("transport closed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (t *memTransport) Addr() string { return "mem" }
func (t *memTransport) Close() error {
	select {
	case <-t.closed:
	default:
		close(t.closed)
	}
	return nil
}

// fakeLauncher records every Launch call and returns a fixed result/error.
type fakeLauncher struct {
	result *Launched
	err    error
	calls  []LaunchSpec
	peers  []PeerIdentity
}

func (f *fakeLauncher) Launch(peer PeerIdentity, spec LaunchSpec) (*Launched, error) {
	f.calls = append(f.calls, spec)
	f.peers = append(f.peers, peer)
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

type fakeIdentifier struct{ publisher string }

func (f fakeIdentifier) Groups(PeerIdentity) ([]string, error) { return nil, nil }
func (f fakeIdentifier) Publisher(string) (string, error)      { return f.publisher, nil }

type fakeRuleProvider struct{ rules []PolicyRule }

func (f fakeRuleProvider) GetRules() ([]PolicyRule, error) { return f.rules, nil }

type fakeAuditSink struct{ entries []AuditEntry }

func (f *fakeAuditSink) InsertAuditLog(entry AuditEntry) error {
	f.entries = append(f.entries, entry)
	return nil
}

// serverTestFixture bundles a running Server (over memTransport) with the
// hooks a test needs to drive it and inspect what happened.
type serverTestFixture struct {
	transport *memTransport
	launcher  *fakeLauncher
	auditor   *fakeAuditSink
	server    *Server
	cancel    context.CancelFunc
}

func newServerTestFixture(t *testing.T, rules []PolicyRule, opts ...ServerOption) *serverTestFixture {
	t.Helper()
	transport := newMemTransport()
	launcher := &fakeLauncher{result: &Launched{ProcessID: 4242}}
	audit := &fakeAuditSink{}
	auditor := NewAuditor(audit)

	allOpts := append([]ServerOption{
		WithHashFile(func(string) (string, error) { return "deadbeef", nil }),
	}, opts...)
	srv := NewServer(transport, launcher, fakeIdentifier{}, fakeRuleProvider{rules: rules}, auditor, allOpts...)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx) }()
	t.Cleanup(cancel)

	return &serverTestFixture{transport: transport, launcher: launcher, auditor: audit, server: srv, cancel: cancel}
}

// send delivers env as one server connection (fresh net.Pipe() per call, one
// request/response exchange, exactly matching every real transport's
// one-elevation-per-connection model) and returns the decoded Response.
func (f *serverTestFixture) send(t *testing.T, env Envelope, peer PeerIdentity) Response {
	t.Helper()
	serverSide, clientSide := net.Pipe()
	f.transport.conns <- newPipeConn(serverSide, peer)

	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	done := make(chan Response, 1)
	errCh := make(chan error, 1)
	go func() {
		if _, err := clientSide.Write(append(data, '\n')); err != nil {
			errCh <- err
			return
		}
		var resp Response
		if err := json.NewDecoder(clientSide).Decode(&resp); err != nil {
			errCh <- err
			return
		}
		done <- resp
	}()

	select {
	case resp := <-done:
		return resp
	case err := <-errCh:
		t.Fatalf("client round trip: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for response")
	}
	return Response{}
}

func TestServer_V1Elevate_Allowed(t *testing.T) {
	f := newServerTestFixture(t, []PolicyRule{{ID: "allow-hash", AppHash: "deadbeef", Decision: DecisionAllow}})

	resp := f.send(t, Envelope{RequestID: "req-1", AppPath: testAppPath()}, PeerIdentity{UserID: "alice"})

	if !resp.Allowed {
		t.Fatalf("expected allowed, got %+v", resp)
	}
	if resp.ProcessID != 4242 {
		t.Errorf("ProcessID = %d, want 4242", resp.ProcessID)
	}
	if resp.RuleID != "allow-hash" {
		t.Errorf("RuleID = %q, want allow-hash", resp.RuleID)
	}
	if len(f.launcher.calls) != 1 {
		t.Fatalf("want 1 launch call, got %d", len(f.launcher.calls))
	}
	if f.launcher.peers[0].UserID != "alice" {
		t.Errorf("Launch's peer.UserID = %q, want alice", f.launcher.peers[0].UserID)
	}
	if len(f.auditor.entries) != 1 || f.auditor.entries[0].Decision != DecisionAllow {
		t.Errorf("audit entries = %+v, want one allow entry", f.auditor.entries)
	}
}

func TestServer_Audit_Phase8FieldsPopulated(t *testing.T) {
	f := newServerTestFixture(t,
		[]PolicyRule{{ID: "allow-hash", AppHash: "deadbeef", Decision: DecisionAllow}},
		WithAgentVersion("9.9.9"),
	)

	resp := f.send(t, Envelope{RequestID: "req-enrich", AppPath: testAppPath(), CommandLine: "tool.exe --flag"}, PeerIdentity{UserID: "alice"})
	if !resp.Allowed {
		t.Fatalf("expected allowed, got %+v", resp)
	}

	if len(f.auditor.entries) != 1 {
		t.Fatalf("audit entries = %+v, want exactly 1", f.auditor.entries)
	}
	got := f.auditor.entries[0]

	if got.SchemaVersion != 2 {
		t.Errorf("SchemaVersion = %d, want 2", got.SchemaVersion)
	}
	if got.Verdict != VerdictAllow {
		t.Errorf("Verdict = %q, want allow", got.Verdict)
	}
	if got.ProcessID != 4242 {
		t.Errorf("ProcessID = %d, want 4242 (from the fake launcher's fixed result)", got.ProcessID)
	}
	if got.CommandLine != "tool.exe --flag" {
		t.Errorf("CommandLine = %q, want %q", got.CommandLine, "tool.exe --flag")
	}
	if got.AgentVersion != "9.9.9" {
		t.Errorf("AgentVersion = %q, want 9.9.9 (from WithAgentVersion)", got.AgentVersion)
	}
	if got.MatchedConditions == "" {
		t.Error("MatchedConditions is empty, want the winning rule's matched condition kinds as JSON")
	}
}

func TestServer_Audit_WithoutAgentVersionOptionLeavesItEmpty(t *testing.T) {
	f := newServerTestFixture(t, []PolicyRule{{ID: "allow-hash", AppHash: "deadbeef", Decision: DecisionAllow}})

	f.send(t, Envelope{RequestID: "req-noversion", AppPath: testAppPath()}, PeerIdentity{UserID: "alice"})

	if len(f.auditor.entries) != 1 {
		t.Fatalf("audit entries = %+v, want exactly 1", f.auditor.entries)
	}
	if got := f.auditor.entries[0].AgentVersion; got != "" {
		t.Errorf("AgentVersion = %q, want empty when WithAgentVersion was never set", got)
	}
}

func TestServer_V1Elevate_Denied(t *testing.T) {
	f := newServerTestFixture(t, []PolicyRule{{ID: "allow-hash", AppHash: "other-hash", Decision: DecisionAllow}})

	resp := f.send(t, Envelope{RequestID: "req-2", AppPath: testAppPath()}, PeerIdentity{UserID: "bob"})

	if resp.Allowed {
		t.Fatalf("expected denied, got %+v", resp)
	}
	if len(f.launcher.calls) != 0 {
		t.Error("a denied request must never reach the launcher")
	}
	if len(f.auditor.entries) != 1 || f.auditor.entries[0].Decision != DecisionDeny {
		t.Errorf("audit entries = %+v, want one deny entry", f.auditor.entries)
	}
}

func TestServer_V2Elevate_ViaBody(t *testing.T) {
	f := newServerTestFixture(t, []PolicyRule{{ID: "allow-hash", AppHash: "deadbeef", Decision: DecisionAllow}})

	body, err := json.Marshal(ElevateBody{AppPath: testAppPath()})
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{ProtocolVersion: 2, Op: OpElevate, RequestID: "req-3", Body: body}
	resp := f.send(t, env, PeerIdentity{UserID: "alice"})

	if !resp.Allowed {
		t.Fatalf("expected allowed, got %+v", resp)
	}
	if resp.ProtocolVersion != 2 {
		t.Errorf("ProtocolVersion = %d, want 2 echoed back", resp.ProtocolVersion)
	}
}

func TestServer_LaunchFailure_FlipsAllowedFalse(t *testing.T) {
	f := newServerTestFixture(t, []PolicyRule{{ID: "allow-hash", AppHash: "deadbeef", Decision: DecisionAllow}})
	f.launcher.err = errors.New("CreateProcessAsUser failed")

	resp := f.send(t, Envelope{RequestID: "req-4", AppPath: testAppPath()}, PeerIdentity{UserID: "alice"})

	if resp.Allowed {
		t.Fatal("Allowed must be false when the launch itself fails")
	}
	if resp.Error == "" {
		t.Error("expected a launch-failure error message")
	}
	// The audit trail must reflect what actually happened (a failed launch),
	// not what policy merely permitted — see server.go's legacyDecisionForAudit.
	if len(f.auditor.entries) != 1 || f.auditor.entries[0].Decision != DecisionDeny {
		t.Errorf("audit entries = %+v, want one deny entry (launch failed)", f.auditor.entries)
	}
}

func TestServer_UnsupportedOp_ReturnsStructuredError(t *testing.T) {
	f := newServerTestFixture(t, nil)
	env := Envelope{ProtocolVersion: 2, Op: OpApprovalPoll, RequestID: "req-5"}
	resp := f.send(t, env, PeerIdentity{})

	if resp.Error == "" {
		t.Error("expected an error naming the unsupported operation")
	}
	if resp.RequestID != "req-5" {
		t.Errorf("RequestID = %q, want req-5 (echoed even on error)", resp.RequestID)
	}
}

// TestServer_MalformedRequest_DoesNotCrashServer covers non-JSON bytes on a
// connection using streaming-JSON framing (unixConn's real framing, and this
// test's pipeConn stand-in for it). Unlike the Windows transport — where
// ReadMessage returns whatever bytes ReadFile got, and a JSON parse failure
// is caught by DecodeRequest inside handleConn, which DOES write an error
// Response — a *unixConn's* ReadMessage decodes JSON as part of framing
// itself (json.Decoder.Decode has to parse enough to find one message's
// boundary), so fundamentally invalid JSON fails there, before
// handleConn ever gets bytes to hand to DecodeRequest. The connection is
// simply closed with nothing written back.
//
// This is not a Phase 2 regression: pre-Phase-2 socket_linux.go/
// socket_darwin.go had the exact same behavior (json.NewDecoder(conn).Decode
// failing just logged and returned). What actually matters here, and what
// this test verifies, is that the one bad connection does not take the
// server down — the next connection must still work normally.
func TestServer_MalformedRequest_DoesNotCrashServer(t *testing.T) {
	f := newServerTestFixture(t, []PolicyRule{{ID: "allow-hash", AppHash: "deadbeef", Decision: DecisionAllow}})

	serverSide, clientSide := net.Pipe()
	f.transport.conns <- newPipeConn(serverSide, PeerIdentity{})
	if _, err := clientSide.Write([]byte("not json at all\n")); err != nil {
		t.Fatal(err)
	}
	var resp Response
	if err := json.NewDecoder(clientSide).Decode(&resp); err == nil {
		t.Error("expected the connection to close with nothing written, matching pre-Phase-2 Unix framing behavior")
	}
	_ = clientSide.Close()

	// The server must still be alive for the next connection.
	resp2 := f.send(t, Envelope{RequestID: "req-6", AppPath: testAppPath()}, PeerIdentity{UserID: "alice"})
	if !resp2.Allowed {
		t.Fatalf("server did not survive a malformed request: %+v", resp2)
	}
}

// TestServer_InteractionVerdict_FallsBackWhenNoPromptDriver proves an
// AuditOnly/Prompt/etc-carrying v2 rule (unreachable via UpgradeV1, only
// reachable through WithEngine — the path Phase 3's BundleManager will use)
// degrades safely: Phase 2 has no way to actually prompt anyone, so a
// RequireApproval rule must resolve via its FallbackVerdict, never silently
// granting.
func TestServer_InteractionVerdict_FallsBackToDenyByDefault(t *testing.T) {
	rule := RuleV2{
		ID: "needs-approval", Enabled: true,
		Conditions: leaf(CondPath, OpEquals, normalizeSeparators(testAppPath())),
		Outcome:    Outcome{Verdict: VerdictRequireApproval}, // FallbackVerdict unset -> deny
	}
	set, issues, err := Compile([]RuleV2{rule}, nil, DefaultMatchers())
	if err != nil || len(issues) != 0 {
		t.Fatalf("Compile: err=%v issues=%v", err, issues)
	}
	engine := NewEngineWithSet(set)

	f := newServerTestFixture(t, nil, WithEngine(engine))
	resp := f.send(t, Envelope{RequestID: "req-7", AppPath: testAppPath()}, PeerIdentity{UserID: "alice"})

	if resp.Allowed {
		t.Fatal("an interaction verdict with no way to interact must not silently grant")
	}
	if resp.Verdict != VerdictRequireApproval {
		t.Errorf("Verdict = %s, want require_approval (the rule's actual prescription, reported even though it fell back)", resp.Verdict)
	}
	if len(f.launcher.calls) != 0 {
		t.Error("must not launch when falling back to deny")
	}
}

func TestServer_AuditOnlyVerdict_ViaWithEngine(t *testing.T) {
	rule := RuleV2{
		ID: "audit-only", Enabled: true,
		Conditions: leaf(CondPath, OpEquals, normalizeSeparators(testAppPath())),
		Outcome:    Outcome{Verdict: VerdictAuditOnly},
	}
	set, _, err := Compile([]RuleV2{rule}, nil, DefaultMatchers())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	engine := NewEngineWithSet(set)

	f := newServerTestFixture(t, nil, WithEngine(engine))
	resp := f.send(t, Envelope{RequestID: "req-8", AppPath: testAppPath()}, PeerIdentity{UserID: "alice"})

	if !resp.Allowed {
		t.Fatal("audit_only should still project to Allowed=true in the legacy response field")
	}
	if resp.Verdict != VerdictAuditOnly {
		t.Errorf("Verdict = %s, want audit_only", resp.Verdict)
	}
	if len(f.launcher.calls) != 1 {
		t.Errorf("audit_only is allow-family and should still launch, got %d launch calls", len(f.launcher.calls))
	}
}

func TestServer_ConstraintsSurfacedInResponse(t *testing.T) {
	rule := RuleV2{
		ID: "constrained", Enabled: true,
		Conditions: leaf(CondPath, OpEquals, normalizeSeparators(testAppPath())),
		Outcome: Outcome{
			Verdict:     VerdictAllow,
			Constraints: Constraints{TokenType: TokenSystem, ChildProcess: ChildDeny},
		},
	}
	set, _, err := Compile([]RuleV2{rule}, nil, DefaultMatchers())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	f := newServerTestFixture(t, nil, WithEngine(NewEngineWithSet(set)))

	resp := f.send(t, Envelope{RequestID: "req-9", AppPath: testAppPath()}, PeerIdentity{UserID: "alice"})

	if resp.Constraints == nil {
		t.Fatal("expected Constraints to be populated in the response")
	}
	if resp.Constraints.TokenType != TokenSystem || resp.Constraints.ChildProcess != ChildDeny {
		t.Errorf("Constraints = %+v, want TokenSystem/ChildDeny", resp.Constraints)
	}
}
