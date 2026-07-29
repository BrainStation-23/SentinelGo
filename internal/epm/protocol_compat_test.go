package epm

// protocol_compat_test.go asserts that a v2 Response marshals to JSON that
// unmarshals cleanly into the OLD v1 wire structs — pipeResponse
// (pipe_windows.go) and socketResponse (socket_linux.go/socket_darwin.go) —
// with identical field values. Those types no longer exist in the
// production code (Phase 2 deleted them in favor of the shared Response),
// so frozen copies are declared here, deliberately never touched again: this
// file's whole purpose is pinning what a pre-Phase-2 client, still running
// today's exact old parsing code, receives from the new server.

import (
	"encoding/json"
	"testing"
)

// frozenPipeResponse is pipe_windows.go's pipeResponse exactly as it existed
// before Phase 2 (see git history) — a v1 client parses server responses
// with a struct shaped exactly like this one.
type frozenPipeResponse struct {
	RequestID string `json:"request_id"`
	Allowed   bool   `json:"allowed"`
	Reason    string `json:"reason"`
	ProcessID uint32 `json:"process_id,omitempty"`
	Error     string `json:"error,omitempty"`
}

// frozenSocketResponse is socket_linux.go's/socket_darwin.go's socketResponse
// exactly as it existed before Phase 2 — field-for-field identical to
// frozenPipeResponse (the "triplicated response struct" Phase 2 eliminated).
type frozenSocketResponse = frozenPipeResponse

func TestResponse_CompatibleWithFrozenV1PipeResponse(t *testing.T) {
	resp := Response{
		RequestID: "req-1", Allowed: true, Reason: "allow",
		ProcessID: 4242,
		// v2-only fields — must be silently ignored by a v1 client's
		// no-DisallowUnknownFields json.Unmarshal, exactly like the real
		// pipe_client_windows.go/socket_client_linux.go/socket_client_darwin.go
		// do (none of them set DisallowUnknownFields).
		ProtocolVersion: 2, Verdict: VerdictAllow, RuleID: "rule-1",
		BundleID: "bundle-1", GrantID: "grant-1", ApprovalID: "approval-1",
		Constraints: &Constraints{TokenType: TokenSystem},
		Explain:     []ExplainStep{{Kind: CondPath, Result: TriTrue}},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var legacy frozenPipeResponse
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatalf("a v1 client's Unmarshal must never fail on a v2 response: %v", err)
	}
	if legacy.RequestID != resp.RequestID || legacy.Allowed != resp.Allowed ||
		legacy.Reason != resp.Reason || legacy.ProcessID != resp.ProcessID {
		t.Errorf("legacy = %+v, fields do not match the v2 response %+v", legacy, resp)
	}
	if legacy.Error != "" {
		t.Errorf("Error = %q, want empty for an allowed response", legacy.Error)
	}
}

func TestResponse_CompatibleWithFrozenV1SocketResponse(t *testing.T) {
	resp := Response{
		RequestID: "req-2", Allowed: false, Reason: "no matching policy (default deny)",
		Verdict: VerdictDeny,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var legacy frozenSocketResponse
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatalf("a v1 client's Unmarshal must never fail on a v2 response: %v", err)
	}
	if legacy.Allowed || legacy.Reason != resp.Reason {
		t.Errorf("legacy = %+v, fields do not match the v2 response %+v", legacy, resp)
	}
}

func TestResponse_ErrorFieldSurvivesToLegacyClient(t *testing.T) {
	resp := Response{RequestID: "req-3", Error: "invalid app_path: app_path must not be empty"}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	var legacy frozenPipeResponse
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if legacy.Error != resp.Error {
		t.Errorf("legacy.Error = %q, want %q", legacy.Error, resp.Error)
	}
}

// TestEnvelope_V1ClientRequestUnaffectedByV2Fields proves the reverse
// direction: a v1 client's literal request struct (frozenPipeRequest below,
// what pipe_windows.go's pipeRequest/socket_linux.go's socketRequest looked
// like) marshals to bytes that DecodeRequest still reads as v1/elevate with
// every field intact — the server-side half of the same compatibility
// guarantee.
type frozenPipeRequest struct {
	RequestID   string `json:"request_id"`
	AppPath     string `json:"app_path"`
	CommandLine string `json:"command_line"`
	ScriptPath  string `json:"script_path,omitempty"`
	Args        string `json:"args,omitempty"`
}

func TestEnvelope_V1ClientRequestUnaffectedByV2Fields(t *testing.T) {
	legacyReq := frozenPipeRequest{
		RequestID: "req-4", AppPath: `C:\apps\tool.exe`, CommandLine: "--flag",
	}
	data, err := json.Marshal(legacyReq)
	if err != nil {
		t.Fatal(err)
	}

	version, op, body, requestID, err := DecodeRequest(data)
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	if version != 1 || op != OpElevate || requestID != legacyReq.RequestID {
		t.Fatalf("version=%d op=%q requestID=%q, want 1/elevate/%q", version, op, requestID, legacyReq.RequestID)
	}
	var elevate ElevateBody
	if err := json.Unmarshal(body, &elevate); err != nil {
		t.Fatal(err)
	}
	if elevate.AppPath != legacyReq.AppPath || elevate.CommandLine != legacyReq.CommandLine {
		t.Errorf("body = %+v, fields not preserved from legacy request %+v", elevate, legacyReq)
	}
}
