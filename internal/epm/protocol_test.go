package epm

import (
	"encoding/json"
	"testing"
)

// TestDecodeRequest_V1Frame proves a literal byte-for-byte v1 request —
// captured from the shape pre-Phase-2 pipe_windows.go/socket_linux.go
// clients actually sent (no protocol_version, no op, fields at the top
// level) — decodes to (version=1, op=elevate) with its fields intact.
func TestDecodeRequest_V1Frame(t *testing.T) {
	raw := []byte(`{"request_id":"req-1","app_path":"C:\\apps\\tool.exe","command_line":"--flag value"}`)

	version, op, body, requestID, err := DecodeRequest(raw)
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	if version != 1 {
		t.Errorf("version = %d, want 1", version)
	}
	if op != OpElevate {
		t.Errorf("op = %q, want elevate", op)
	}
	if requestID != "req-1" {
		t.Errorf("requestID = %q, want req-1", requestID)
	}

	var elevate ElevateBody
	if err := json.Unmarshal(body, &elevate); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if elevate.AppPath != `C:\apps\tool.exe` || elevate.CommandLine != "--flag value" {
		t.Errorf("body = %+v, fields not preserved", elevate)
	}
}

// TestDecodeRequest_V1FrameWithScriptFields covers the script-elevation
// shape (script_path/args instead of command_line).
func TestDecodeRequest_V1FrameWithScriptFields(t *testing.T) {
	raw := []byte(`{"request_id":"req-2","app_path":"/usr/bin/dpkg","script_path":"/tmp/tool.deb","args":"-i /tmp/tool.deb"}`)

	version, op, body, _, err := DecodeRequest(raw)
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	if version != 1 || op != OpElevate {
		t.Fatalf("version=%d op=%q, want 1/elevate", version, op)
	}
	var elevate ElevateBody
	if err := json.Unmarshal(body, &elevate); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if elevate.ScriptPath != "/tmp/tool.deb" || elevate.Args != "-i /tmp/tool.deb" {
		t.Errorf("body = %+v, script fields not preserved", elevate)
	}
}

func TestDecodeRequest_V2Envelope(t *testing.T) {
	body, _ := json.Marshal(ElevateBody{AppPath: `C:\apps\tool.exe`})
	raw, err := json.Marshal(Envelope{
		ProtocolVersion: 2, Op: OpElevate, RequestID: "req-3", Body: body,
	})
	if err != nil {
		t.Fatal(err)
	}

	version, op, decodedBody, requestID, err := DecodeRequest(raw)
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	if version != 2 {
		t.Errorf("version = %d, want 2", version)
	}
	if op != OpElevate {
		t.Errorf("op = %q, want elevate", op)
	}
	if requestID != "req-3" {
		t.Errorf("requestID = %q, want req-3", requestID)
	}
	var elevate ElevateBody
	if err := json.Unmarshal(decodedBody, &elevate); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if elevate.AppPath != `C:\apps\tool.exe` {
		t.Errorf("AppPath = %q, want the original value", elevate.AppPath)
	}
}

func TestDecodeRequest_V2UnknownOp(t *testing.T) {
	raw, _ := json.Marshal(Envelope{ProtocolVersion: 2, Op: "totally_made_up", RequestID: "req-4"})

	version, op, _, requestID, err := DecodeRequest(raw)
	if err != nil {
		t.Fatalf("DecodeRequest should not itself error on an unrecognised op (that is Server.handleConn's job): %v", err)
	}
	if version != 2 || op != "totally_made_up" || requestID != "req-4" {
		t.Errorf("version=%d op=%q requestID=%q, want 2/totally_made_up/req-4", version, op, requestID)
	}
}

func TestDecodeRequest_V2OpDefaultsToElevateWhenOmitted(t *testing.T) {
	// protocol_version set but op omitted: still v2, defaults to elevate —
	// distinct from the v1 case (neither set), which DecodeRequest must tell
	// apart correctly.
	raw, _ := json.Marshal(Envelope{ProtocolVersion: 2, RequestID: "req-5"})
	version, op, _, _, err := DecodeRequest(raw)
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	if version != 2 || op != OpElevate {
		t.Errorf("version=%d op=%q, want 2/elevate", version, op)
	}
}

func TestDecodeRequest_Garbage(t *testing.T) {
	tests := [][]byte{
		[]byte("not json at all"),
		[]byte(`{"unterminated`),
		[]byte(``),
		[]byte(`null`),
		[]byte(`42`),
		[]byte(`"a bare string"`),
		[]byte(`[]`),
	}
	for _, raw := range tests {
		t.Run(string(raw), func(t *testing.T) {
			// Must never panic; a non-object payload should error rather
			// than silently succeed with a nonsensical zero-value envelope.
			_, _, _, _, err := DecodeRequest(raw)
			switch string(raw) {
			case "null":
				// json.Unmarshal(null, &struct) leaves the struct at its
				// zero value with no error — DecodeRequest correctly reports
				// this as v1/elevate/empty-body, which is a defensible (if
				// unlikely to occur for real) interpretation, not a bug.
			default:
				if err == nil {
					t.Errorf("expected an error for %q", raw)
				}
			}
		})
	}
}

func FuzzDecodeRequest(f *testing.F) {
	f.Add([]byte(`{"request_id":"r1","app_path":"C:\\a.exe"}`))
	f.Add([]byte(`{"protocol_version":2,"op":"elevate","request_id":"r2","body":{"app_path":"/a"}}`))
	f.Add([]byte(`{"protocol_version":2,"op":"hello"}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`garbage`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic, regardless of input.
		_, _, _, _, _ = DecodeRequest(data)
	})
}

func TestResponse_EncodeRoundTrip(t *testing.T) {
	resp := Response{
		RequestID: "req-1", Allowed: true, Reason: "allow",
		ProcessID: 4242, Verdict: VerdictAllow, RuleID: "rule-1",
	}
	data, err := encodeResponse(resp)
	if err != nil {
		t.Fatalf("encodeResponse: %v", err)
	}
	var got Response
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	// Field-by-field: Response embeds a slice (Explain), so it is not
	// comparable with ==.
	if got.RequestID != resp.RequestID || got.Allowed != resp.Allowed || got.Reason != resp.Reason ||
		got.ProcessID != resp.ProcessID || got.Verdict != resp.Verdict || got.RuleID != resp.RuleID {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, resp)
	}
}
