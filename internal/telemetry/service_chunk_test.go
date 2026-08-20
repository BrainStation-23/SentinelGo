package telemetry

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/config"
)

// chunkedWireEnvelope is the subset of the wire format these tests assert on.
type chunkedWireEnvelope struct {
	Payload struct {
		Class                string     `json:"class"`
		Sections             []string   `json:"sections"`
		CollectionGeneration uint64     `json:"collection_generation"`
		Chunk                *ChunkMeta `json:"chunk"`
		Data                 struct {
			Processes []fakeProcess `json:"processes"`
		} `json:"data"`
	} `json:"payload"`
}

func TestCycleSendsAuthoritativeEmptyChunkedSnapshot(t *testing.T) {
	c := &fakeCollector{
		name: "processes", section: SectionProcesses,
		capKey: CapKeyProcesses, capState: CapSupported,
		payload: []fakeProcess{},
	}
	svc, _, queue := newTestService(t, c)
	svc.SetClock(func() time.Time { return baseTime })

	report, err := svc.RunCycle(context.Background(), &config.Config{DeviceID: "dev-1"})
	if err != nil {
		t.Fatalf("cycle: %v", err)
	}
	if report.Messages != 1 || len(queue.messages) != 1 {
		t.Fatalf("empty authoritative snapshot produced %d messages, want 1", len(queue.messages))
	}
	env := decodeChunked(t, queue.messages[0].Payload)
	if env.Payload.Chunk == nil || env.Payload.Chunk.BatchCount != 1 || env.Payload.Chunk.TotalItems != 0 {
		t.Fatalf("invalid empty snapshot metadata: %+v", env.Payload.Chunk)
	}
	if env.Payload.Data.Processes == nil || len(env.Payload.Data.Processes) != 0 {
		t.Fatalf("empty snapshot must carry an explicit empty array, got %#v", env.Payload.Data.Processes)
	}
}

func TestCycleUsesOneMonotonicGenerationAcrossChunks(t *testing.T) {
	c := &fakeCollector{
		name: "processes", section: SectionProcesses,
		capKey: CapKeyProcesses, capState: CapSupported,
		payload: makeProcesses(4000, 2048),
	}
	svc, state, queue := newTestService(t, c)
	svc.SetClock(func() time.Time { return baseTime })

	if _, err := svc.RunCycle(context.Background(), &config.Config{DeviceID: "dev-1"}); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	if len(queue.messages) < 2 {
		t.Fatalf("expected multiple chunks, got %d", len(queue.messages))
	}
	for i, msg := range queue.messages {
		env := decodeChunked(t, msg.Payload)
		if env.Payload.CollectionGeneration != 1 {
			t.Errorf("chunk %d generation = %d, want 1", i, env.Payload.CollectionGeneration)
		}
	}
	if state.generation != 1 {
		t.Errorf("allocated %d generations for one cycle, want 1", state.generation)
	}
}

func decodeChunked(t *testing.T, payload []byte) chunkedWireEnvelope {
	t.Helper()
	var env chunkedWireEnvelope
	if err := json.Unmarshal(payload, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	return env
}

// TestCycleChunksHighCardinalitySection is the end-to-end proof that a large
// section is split before it reaches the outbound queue, rather than being
// enqueued as one oversized message that the backend would reject.
func TestCycleChunksHighCardinalitySection(t *testing.T) {
	// SectionProcesses is registered as Chunked in the default registry.
	procs := makeProcesses(4000, 2048) // ~8 MB, far past the 900 KB cap

	c := &fakeCollector{
		name: "processes", section: SectionProcesses,
		capKey: CapKeyProcesses, capState: CapSupported,
		payload: procs,
	}
	svc, _, queue := newTestService(t, c)
	svc.SetClock(func() time.Time { return baseTime })

	report, err := svc.RunCycle(context.Background(), &config.Config{DeviceID: "dev-1"})
	if err != nil {
		t.Fatalf("cycle: %v", err)
	}

	if len(queue.messages) < 2 {
		t.Fatalf("expected the section to be chunked, got %d message(s)", len(queue.messages))
	}
	if report.Messages != len(queue.messages) {
		t.Errorf("report.Messages = %d, want %d", report.Messages, len(queue.messages))
	}

	var (
		snapshotIDs = map[string]bool{}
		seenIndex   = map[int]bool{}
		itemsSeen   int
		batchCount  int
	)

	for i, msg := range queue.messages {
		if len(msg.Payload) > MaxPayloadBytes {
			t.Errorf("message %d is %d bytes, over the %d cap", i, len(msg.Payload), MaxPayloadBytes)
		}

		env := decodeChunked(t, msg.Payload)
		if env.Payload.Chunk == nil {
			t.Fatalf("message %d has no chunk metadata", i)
		}
		ch := env.Payload.Chunk

		snapshotIDs[ch.SnapshotID] = true
		seenIndex[ch.BatchIndex] = true
		batchCount = ch.BatchCount
		itemsSeen += len(env.Payload.Data.Processes)

		if ch.TotalItems != len(procs) {
			t.Errorf("message %d reports total_items %d, want %d", i, ch.TotalItems, len(procs))
		}
		if ch.Truncated {
			t.Errorf("message %d is marked truncated, but every item fits", i)
		}
		// The queue row must carry the same batch coordinates as the payload, so
		// a retry replays an identical logical batch.
		if msg.BatchIndex != ch.BatchIndex || msg.BatchCount != ch.BatchCount {
			t.Errorf("message %d queue coords (%d/%d) disagree with payload (%d/%d)",
				i, msg.BatchIndex, msg.BatchCount, ch.BatchIndex, ch.BatchCount)
		}
		if msg.SnapshotID != ch.SnapshotID {
			t.Errorf("message %d queue snapshot %q disagrees with payload %q",
				i, msg.SnapshotID, ch.SnapshotID)
		}
	}

	// One logical snapshot, dense 0-based indices, nothing lost.
	if len(snapshotIDs) != 1 {
		t.Fatalf("expected one snapshot_id across all batches, got %d", len(snapshotIDs))
	}
	if batchCount != len(queue.messages) {
		t.Errorf("batch_count = %d, want %d", batchCount, len(queue.messages))
	}
	for i := 0; i < batchCount; i++ {
		if !seenIndex[i] {
			t.Errorf("batch index %d missing", i)
		}
	}
	if itemsSeen != len(procs) {
		t.Fatalf("chunking lost data: %d items delivered, want %d", itemsSeen, len(procs))
	}
}

// TestCycleMarksTruncatedWhenItemCannotFit covers the only case where data loss
// is permitted: a single item too large for any batch. It must be reported in
// the payload, the cycle report and telemetry health — never dropped silently.
func TestCycleMarksTruncatedWhenItemCannotFit(t *testing.T) {
	procs := []fakeProcess{
		{PID: 1, Name: "small.exe", Cmdline: "x"},
		// One item larger than the whole message budget.
		{PID: 2, Name: "monster.exe", Cmdline: strings.Repeat("y", MaxPayloadBytes+50_000)},
		{PID: 3, Name: "small2.exe", Cmdline: "z"},
	}

	c := &fakeCollector{
		name: "processes", section: SectionProcesses,
		capKey: CapKeyProcesses, capState: CapSupported,
		payload: procs,
	}
	svc, _, queue := newTestService(t, c)
	svc.SetClock(func() time.Time { return baseTime })

	report, err := svc.RunCycle(context.Background(), &config.Config{DeviceID: "dev-1"})
	if err != nil {
		t.Fatalf("cycle: %v", err)
	}

	if len(queue.messages) == 0 {
		t.Fatal("the sendable items must still be delivered")
	}

	env := decodeChunked(t, queue.messages[0].Payload)
	if env.Payload.Chunk == nil || !env.Payload.Chunk.Truncated {
		t.Fatal("snapshot must be marked truncated when an item cannot be sent")
	}
	if env.Payload.Chunk.TotalItems != len(procs) {
		t.Errorf("total_items = %d, want %d (the true count, before exclusion)",
			env.Payload.Chunk.TotalItems, len(procs))
	}
	// An explicit count, not just a boolean: total_items minus excluded_items is
	// exactly what the backend should expect to reassemble, so a truncated
	// snapshot can be reconciled rather than merely flagged.
	if env.Payload.Chunk.ExcludedItems != 1 {
		t.Errorf("excluded_items = %d, want 1", env.Payload.Chunk.ExcludedItems)
	}
	expected := env.Payload.Chunk.TotalItems - env.Payload.Chunk.ExcludedItems
	if expected != 2 {
		t.Errorf("total_items - excluded_items = %d, want 2 (the deliverable set)", expected)
	}

	if !strings.Contains(string(queue.messages[0].Payload), `"excluded_items":1`) {
		t.Errorf("wire payload must carry excluded_items; got: %s",
			truncateForLog(string(queue.messages[0].Payload)))
	}

	if !containsString(report.Truncated, SectionProcesses) {
		t.Errorf("cycle report should list %q as truncated, got %v", SectionProcesses, report.Truncated)
	}
	if report.Health == nil || report.Health.DroppedEventCount == 0 {
		t.Error("dropped item must be counted in telemetry health, not lost silently")
	}

	// The two sendable items survive.
	var delivered int
	for _, msg := range queue.messages {
		delivered += len(decodeChunked(t, msg.Payload).Payload.Data.Processes)
	}
	if delivered != 2 {
		t.Errorf("delivered %d items, want the 2 that fit", delivered)
	}
}

// TestCycleDoesNotChunkSmallSection avoids needless fragmentation and confirms
// a section that fits carries no chunk block at all.
func TestCycleDoesNotChunkSmallSection(t *testing.T) {
	c := &fakeCollector{
		name: "processes", section: SectionProcesses,
		capKey: CapKeyProcesses, capState: CapSupported,
		payload: makeProcesses(20, 64),
	}
	svc, _, queue := newTestService(t, c)
	svc.SetClock(func() time.Time { return baseTime })

	if _, err := svc.RunCycle(context.Background(), &config.Config{DeviceID: "dev-1"}); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	if len(queue.messages) != 1 {
		t.Fatalf("expected one message for a small section, got %d", len(queue.messages))
	}

	env := decodeChunked(t, queue.messages[0].Payload)
	if env.Payload.Chunk == nil {
		t.Fatal("a chunked section should still carry chunk metadata for reassembly")
	}
	if env.Payload.Chunk.BatchCount != 1 {
		t.Errorf("batch_count = %d, want 1", env.Payload.Chunk.BatchCount)
	}
}

// TestChunkedSectionKeepsOtherSectionsOut verifies a large list does not drag
// unrelated sections into every batch.
func TestChunkedSectionKeepsOtherSectionsOut(t *testing.T) {
	procs := &fakeCollector{
		name: "processes", section: SectionProcesses,
		capKey: CapKeyProcesses, capState: CapSupported,
		payload: makeProcesses(3000, 2048),
	}
	ident := &fakeCollector{
		name: "identity", section: SectionIdentity,
		capKey: CapKeyDirectoryJoin, capState: CapSupported,
		payload: map[string]any{"hostname": "host-1"},
	}
	svc, _, queue := newTestService(t, procs, ident)
	svc.SetClock(func() time.Time { return baseTime })

	if _, err := svc.RunCycle(context.Background(), &config.Config{DeviceID: "dev-1"}); err != nil {
		t.Fatalf("cycle: %v", err)
	}

	var identityMessages int
	for _, msg := range queue.messages {
		env := decodeChunked(t, msg.Payload)
		hasProcesses := containsString(env.Payload.Sections, SectionProcesses)
		hasIdentity := containsString(env.Payload.Sections, SectionIdentity)
		if hasProcesses && hasIdentity {
			t.Error("a chunked section must not be bundled with unrelated sections")
		}
		if hasIdentity {
			identityMessages++
		}
	}
	if identityMessages != 1 {
		t.Errorf("identity should be sent exactly once, got %d messages", identityMessages)
	}
}

// truncateForLog keeps a failure message readable.
func truncateForLog(s string) string {
	if len(s) > 400 {
		return s[:400] + "..."
	}
	return s
}
