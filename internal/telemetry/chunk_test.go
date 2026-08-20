package telemetry

import (
	"encoding/json"
	"errors"
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
// enqueue limit, and exactly the shape that would otherwise be lost.
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
	if len(oversized) != 0 {
		t.Fatalf("no single item should exceed the cap, got %d oversized", len(oversized))
	}
	if len(batches) < 2 {
		t.Fatalf("expected the payload to be split, got %d batch(es)", len(batches))
	}

	total := 0
	for i, batch := range batches {
		encoded, mErr := json.Marshal(batch)
		if mErr != nil {
			t.Fatalf("marshal batch %d: %v", i, mErr)
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

// TestChunkExcludesUnsendableItem covers the one case where truncation is
// permitted: an item whose own encoding exceeds the limit cannot be placed in
// any batch that respects the cap.
//
// It is excluded rather than emitted, because emitting it would guarantee a
// rejected payload and lose the whole batch instead of the single item. The
// exclusion is reported so the caller can mark the snapshot truncated.
func TestChunkExcludesUnsendableItem(t *testing.T) {
	items := []fakeProcess{
		{PID: 1, Name: "small.exe", Cmdline: "x"},
		{PID: 2, Name: "huge.exe", Cmdline: strings.Repeat("y", 2000)},
		{PID: 3, Name: "small2.exe", Cmdline: "z"},
	}

	batches, oversized, err := Chunk(items, 500)
	if err != nil {
		t.Fatalf("chunk: %v", err)
	}
	if len(oversized) != 1 || oversized[0] != 1 {
		t.Fatalf("oversized = %v, want [1]", oversized)
	}

	var flat []fakeProcess
	for _, b := range batches {
		flat = append(flat, b...)
	}
	if len(flat) != 2 {
		t.Fatalf("expected the two sendable items, got %d", len(flat))
	}
	for _, p := range flat {
		if p.PID == 2 {
			t.Fatal("the unsendable item must not be emitted")
		}
	}
	// Every emitted batch must respect the cap.
	for i, b := range batches {
		encoded, _ := json.Marshal(b)
		if len(encoded) > 500 {
			t.Errorf("batch %d is %d bytes, over the 500 cap", i, len(encoded))
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
		meta := ChunkMetaFor(snapshotID, i, len(batches), len(items), 0)
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

// TestChunkSmallInputStaysSingleBatch avoids needless fragmentation.
func TestChunkSmallInputStaysSingleBatch(t *testing.T) {
	batches, oversized, err := Chunk(makeProcesses(10, 64), MaxPayloadBytes)
	if err != nil {
		t.Fatalf("chunk: %v", err)
	}
	if len(oversized) != 0 {
		t.Errorf("oversized = %v, want none", oversized)
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
	if len(batches) != 0 || len(oversized) != 0 {
		t.Fatalf("empty input produced %d batches / %d oversized", len(batches), len(oversized))
	}
}

// ── ChunkSection (the reflective production path) ────────────────────────────

// TestChunkSectionWalksSlicePayload verifies the reflective path used for
// collector-defined `any` payloads matches the typed path.
func TestChunkSectionWalksSlicePayload(t *testing.T) {
	items := makeProcesses(2000, 512)

	batches, totalItems, oversized, err := ChunkSection(any(items), 100_000)
	if err != nil {
		t.Fatalf("ChunkSection: %v", err)
	}
	if totalItems != len(items) {
		t.Errorf("totalItems = %d, want %d", totalItems, len(items))
	}
	if len(oversized) != 0 {
		t.Errorf("oversized = %v, want none", oversized)
	}
	if len(batches) < 2 {
		t.Fatalf("expected multiple batches, got %d", len(batches))
	}

	total := 0
	for _, b := range batches {
		total += len(b)
	}
	if total != len(items) {
		t.Fatalf("reflective chunking lost data: %d, want %d", total, len(items))
	}
}

// TestChunkSectionReportsTotalBeforeExclusion is important for the backend: the
// true set size must be reported even when part of it could not be sent, so a
// truncated snapshot is recognisable rather than looking merely small.
func TestChunkSectionReportsTotalBeforeExclusion(t *testing.T) {
	items := []fakeProcess{
		{PID: 1, Cmdline: "x"},
		{PID: 2, Cmdline: strings.Repeat("y", 5000)},
		{PID: 3, Cmdline: "z"},
	}

	_, totalItems, oversized, err := ChunkSection(any(items), 1000)
	if err != nil {
		t.Fatalf("ChunkSection: %v", err)
	}
	if totalItems != 3 {
		t.Errorf("totalItems = %d, want 3 (the count BEFORE exclusion)", totalItems)
	}
	if len(oversized) != 1 {
		t.Errorf("oversized = %v, want one entry", oversized)
	}
}

// TestChunkSectionRejectsNonSlice checks a misconfigured section is reported
// rather than silently mangled.
func TestChunkSectionRejectsNonSlice(t *testing.T) {
	_, _, _, err := ChunkSection(map[string]any{"not": "a list"}, MaxPayloadBytes)
	if err == nil {
		t.Fatal("expected an error for a non-slice payload")
	}
	if !errors.Is(err, ErrNotChunkable) {
		t.Fatalf("error should be ErrNotChunkable, got %v", err)
	}
}

// TestChunkSectionNilPayload covers the empty case.
func TestChunkSectionNilPayload(t *testing.T) {
	batches, total, oversized, err := ChunkSection(nil, MaxPayloadBytes)
	if err != nil {
		t.Fatalf("ChunkSection(nil): %v", err)
	}
	if len(batches) != 0 || total != 0 || len(oversized) != 0 {
		t.Fatal("nil payload should produce nothing")
	}
}
