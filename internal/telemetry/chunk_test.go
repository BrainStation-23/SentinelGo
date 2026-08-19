package telemetry

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

type fakeProcess struct {
	PID     int    `json:"pid"`
	Name    string `json:"name"`
	Cmdline string `json:"cmdline"`
}

func makeProcesses(n, cmdlineBytes int) []fakeProcess {
	out := make([]fakeProcess, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fakeProcess{
			PID:     1000 + i,
			Name:    fmt.Sprintf("proc-%d.exe", i),
			Cmdline: strings.Repeat("x", cmdlineBytes),
		})
	}
	return out
}

// TestChunkSplitsInsteadOfTruncating is the guarantee that a large inventory is
// delivered in full.
//
// A truncated process or certificate list is indistinguishable from a genuinely
// short one, so dropping the tail would silently misreport the endpoint.
// 5,000 processes with 4 KB command lines is roughly 20 MB — far past the
// enqueue limit, and exactly the shape that would previously have been lost.
func TestChunkSplitsInsteadOfTruncating(t *testing.T) {
	const (
		count        = 5000
		cmdlineBytes = 4096
	)
	items := makeProcesses(count, cmdlineBytes)

	batches, oversized, err := Chunk(items, MaxPayloadBytes)
	if err != nil {
		t.Fatalf("chunk: %v", err)
	}
	if oversized != 0 {
		t.Fatalf("no single item should exceed the cap, got %d oversized", oversized)
	}
	if len(batches) < 2 {
		t.Fatalf("expected the payload to be split, got %d batch(es)", len(batches))
	}

	// Every batch must fit, and the union must be the complete, ordered input.
	total := 0
	for i, batch := range batches {
		encoded, err := json.Marshal(batch)
		if err != nil {
			t.Fatalf("marshal batch %d: %v", i, err)
		}
		if len(encoded) > MaxPayloadBytes {
			t.Errorf("batch %d is %d bytes, over the %d cap", i, len(encoded), MaxPayloadBytes)
		}
		total += len(batch)
	}
	if total != count {
		t.Fatalf("chunking lost data: %d items across batches, want %d", total, count)
	}

	// Order must be preserved so a sorted input stays sorted end to end.
	flat := make([]fakeProcess, 0, count)
	for _, b := range batches {
		flat = append(flat, b...)
	}
	for i := range flat {
		if flat[i].PID != items[i].PID {
			t.Fatalf("order not preserved at %d: got PID %d, want %d", i, flat[i].PID, items[i].PID)
		}
	}
}

// TestChunkMetaDescribesTheSnapshot checks the fields the backend needs to
// reassemble a snapshot and to notice a missing batch.
func TestChunkMetaDescribesTheSnapshot(t *testing.T) {
	items := makeProcesses(3000, 1024)
	batches, _, err := Chunk(items, MaxPayloadBytes)
	if err != nil {
		t.Fatalf("chunk: %v", err)
	}

	snapshotID := NewSnapshotID()
	if snapshotID == "" {
		t.Fatal("snapshot id must not be empty")
	}

	seen := make(map[int]bool)
	for i := range batches {
		meta := ChunkMetaFor(snapshotID, i, len(batches), len(items))
		if meta.SnapshotID != snapshotID {
			t.Errorf("batch %d has snapshot id %q, want %q", i, meta.SnapshotID, snapshotID)
		}
		if meta.BatchCount != len(batches) {
			t.Errorf("batch %d reports count %d, want %d", i, meta.BatchCount, len(batches))
		}
		if meta.TotalItems != len(items) {
			t.Errorf("batch %d reports %d total items, want %d", i, meta.TotalItems, len(items))
		}
		if meta.Truncated {
			t.Errorf("batch %d must not be marked truncated", i)
		}
		seen[meta.BatchIndex] = true
	}

	for i := 0; i < len(batches); i++ {
		if !seen[i] {
			t.Errorf("batch index %d missing; indices must be dense and 0-based", i)
		}
	}
}

// TestChunkSnapshotIDsAreUnique guards against batches of different snapshots
// being merged by the backend.
func TestChunkSnapshotIDsAreUnique(t *testing.T) {
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		id := NewSnapshotID()
		if seen[id] {
			t.Fatalf("duplicate snapshot id %q", id)
		}
		seen[id] = true
	}
}

// TestChunkOversizedItemStillEmitted verifies a single item larger than the cap
// is reported but not dropped: losing a real endpoint fact is worse than an
// oversized batch the caller can shrink.
func TestChunkOversizedItemStillEmitted(t *testing.T) {
	items := []fakeProcess{
		{PID: 1, Name: "small.exe", Cmdline: "x"},
		{PID: 2, Name: "huge.exe", Cmdline: strings.Repeat("y", 2000)},
		{PID: 3, Name: "small2.exe", Cmdline: "z"},
	}

	batches, oversized, err := Chunk(items, 500)
	if err != nil {
		t.Fatalf("chunk: %v", err)
	}
	if oversized != 1 {
		t.Fatalf("oversized = %d, want 1", oversized)
	}

	total := 0
	for _, b := range batches {
		total += len(b)
	}
	if total != len(items) {
		t.Fatalf("oversized item was dropped: %d items emitted, want %d", total, len(items))
	}
}

// TestChunkSmallInputStaysSingleBatch avoids needless fragmentation.
func TestChunkSmallInputStaysSingleBatch(t *testing.T) {
	batches, oversized, err := Chunk(makeProcesses(10, 64), MaxPayloadBytes)
	if err != nil {
		t.Fatalf("chunk: %v", err)
	}
	if oversized != 0 {
		t.Errorf("oversized = %d, want 0", oversized)
	}
	if len(batches) != 1 {
		t.Fatalf("expected a single batch for a small payload, got %d", len(batches))
	}
}

// TestChunkEmptyInput checks the empty case produces nothing to send.
func TestChunkEmptyInput(t *testing.T) {
	batches, oversized, err := Chunk([]fakeProcess{}, MaxPayloadBytes)
	if err != nil {
		t.Fatalf("chunk: %v", err)
	}
	if len(batches) != 0 || oversized != 0 {
		t.Fatalf("empty input produced %d batches / %d oversized", len(batches), oversized)
	}
}
