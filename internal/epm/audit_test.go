package epm

import (
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

func TestAuditor_Log_WrapsSinkError(t *testing.T) {
	sinkErr := errors.New("disk full")
	a := NewAuditor(&stubSink{err: sinkErr})

	err := a.Log(AuditEntry{RequestID: "req-2"})
	if err == nil || !errors.Is(err, sinkErr) {
		t.Fatalf("expected wrapped sink error, got %v", err)
	}
}
