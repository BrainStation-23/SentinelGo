package logging

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"sentinelgo/internal/auditlogs/parser"
	"sentinelgo/internal/config"
	"sentinelgo/internal/models"
	"sentinelgo/internal/store"
)

// TestDiscard_DropsQueueKeepsCheckpoints: when the server turns audit logs
// off (#466) the pipeline stops without a final upload, the queue is
// emptied and the checkpoints are saved for a later restart.
func TestDiscard_DropsQueueKeepsCheckpoints(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")
	st, err := store.NewAuditLogStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Insert([]models.AuditLog{{Source: "s", Timestamp: time.Now().UTC().Format(time.RFC3339), EventType: "e"}}); err != nil {
		t.Fatal(err)
	}
	cp := NewCheckpointStore(dir)
	cp.Update(CheckpointData{"s": "cursor-1"})

	_, cancel := context.WithCancel(context.Background())
	li := &LoggingIntegration{
		// No Supabase URL: a final upload, if Discard made one, would fail
		// and leave the row queued.
		cfg:        &config.Config{DeviceID: "dev"},
		parser:     parser.NewParser(),
		store:      st,
		checkpoint: cp,
		cancel:     cancel,
		started:    true,
	}

	if err := li.Discard(); err != nil {
		t.Fatalf("Discard: %v", err)
	}
	if li.started {
		t.Error("still started after Discard")
	}

	st2, err := store.NewAuditLogStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st2.Close() }()
	pending, err := st2.GetPending(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Errorf("%d rows still queued, want 0", len(pending))
	}

	cp2 := NewCheckpointStore(dir)
	if err := cp2.Load(); err != nil {
		t.Fatal(err)
	}
	if got := cp2.Get()["s"]; got != "cursor-1" {
		t.Errorf("checkpoint = %q, want cursor-1 (kept)", got)
	}

	// A second Discard is a no-op.
	if err := li.Discard(); err != nil {
		t.Errorf("second Discard: %v", err)
	}
}
