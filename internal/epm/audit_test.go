package epm

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type stubSink struct {
	entries []AuditEntry
	err     error
}

func (s *stubSink) InsertAuditLog(entry AuditEntry) error {
	if s.err != nil {
		return s.err
	}
	s.entries = append(s.entries, entry)
	return nil
}

func TestAuditor_Log_WritesThroughSink(t *testing.T) {
	sink := &stubSink{}
	a := NewAuditor(sink)

	entry := AuditEntry{
		RequestID:  "req-1",
		UserID:     "alice",
		AppPath:    "/tool",
		Decision:   DecisionAllow,
		LaunchedAt: time.Now(),
	}
	if err := a.Log(entry); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if len(sink.entries) != 1 || sink.entries[0].RequestID != "req-1" {
		t.Errorf("sink.entries = %+v, want one entry with RequestID req-1", sink.entries)
	}
}

// TestAuditEntry_JSONShapeUnchanged pins the wire format
// internal/logging/epm_upload.go's epmAuditLogRecord marshals into
// models.AuditLog.EventData: the explicit json tags added alongside the v2
// engine must reproduce the exact key names Go's default field-name fallback
// produced before any tag existed. A backend consumer parsing EventData today
// depends on these key names; this test is what would catch an accidental
// rename.
func TestAuditEntry_JSONShapeUnchanged(t *testing.T) {
	entry := AuditEntry{
		RequestID: "req-1", UserID: "alice", AppPath: "/tool", AppHash: "abc",
		Decision: DecisionAllow, PolicyID: "rule-1",
		LaunchedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ScriptHash: "def", ServiceName: "MyService",
	}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got map[string]json.RawMessage
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	for _, key := range []string{
		"RequestID", "UserID", "AppPath", "AppHash", "Decision",
		"PolicyID", "LaunchedAt", "ScriptHash", "ServiceName",
	} {
		if _, ok := got[key]; !ok {
			t.Errorf("marshaled JSON is missing expected key %q; keys present: %v", key, keysOf(got))
		}
	}
	if len(got) != 9 {
		t.Errorf("marshaled JSON has %d keys, want exactly 9: %v", len(got), keysOf(got))
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestAuditor_Log_WrapsSinkError(t *testing.T) {
	sinkErr := errors.New("disk full")
	a := NewAuditor(&stubSink{err: sinkErr})

	err := a.Log(AuditEntry{RequestID: "req-2"})
	if err == nil || !errors.Is(err, sinkErr) {
		t.Fatalf("expected wrapped sink error, got %v", err)
	}
}
