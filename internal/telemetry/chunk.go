package telemetry

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// MaxPayloadBytes is the ceiling for a single enqueued message. The backend's
// enqueue limit is 1 MB; this leaves headroom for the envelope wrapper.
//
// The value matches the constant the audit-log uploader already applies. It is
// restated here rather than imported so the telemetry layer stays independent
// of the logging package.
const MaxPayloadBytes = 900_000

// ChunkMeta describes one batch of a chunked, high-cardinality section.
//
// Chunking rather than truncating is deliberate: a truncated process or
// certificate list is indistinguishable from a short one, so silently dropping
// the tail would misreport the endpoint. Splitting preserves the whole set and
// lets the backend reassemble it.
type ChunkMeta struct {
	// SnapshotID ties every batch of one logical snapshot together.
	SnapshotID string `json:"snapshot_id"`
	// BatchIndex is 0-based.
	BatchIndex int `json:"batch_index"`
	BatchCount int `json:"batch_count"`
	// TotalItems is the true item count before any batching, so the backend can
	// verify completeness and detect a lost batch.
	TotalItems int `json:"total_items"`
	// Truncated marks data the agent could not send at all. It is a last-resort
	// safety valve, always surfaced in telemetry health — never a silent drop.
	Truncated bool `json:"truncated,omitempty"`
}

// NewSnapshotID returns a random identifier for one logical snapshot.
func NewSnapshotID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is not recoverable here; fall back to a value that
		// is still unique enough to group batches within one process run.
		return hex.EncodeToString([]byte(fmt.Sprintf("%d", len(b))))
	}
	return hex.EncodeToString(b[:])
}

// Chunk splits items into batches whose encoded JSON stays within maxBytes.
//
// Each item is measured once. Items are packed greedily in order, so a caller
// that sorted its list keeps that order across batches.
//
// oversized counts items that exceed maxBytes on their own. Such an item is
// still emitted, in a batch by itself: the caller is expected to have shrunk
// its heaviest optional field first (for example a process command line), and
// dropping the item entirely would lose a real endpoint fact.
func Chunk[T any](items []T, maxBytes int) (batches [][]T, oversized int, err error) {
	if len(items) == 0 {
		return nil, 0, nil
	}
	if maxBytes <= 0 {
		maxBytes = MaxPayloadBytes
	}

	sizes := make([]int, len(items))
	for i := range items {
		buf, mErr := json.Marshal(items[i])
		if mErr != nil {
			return nil, 0, fmt.Errorf("chunk: marshal item %d: %w", i, mErr)
		}
		// +1 for the separating comma in the encoded array.
		sizes[i] = len(buf) + 1
		if sizes[i] > maxBytes {
			oversized++
		}
	}

	var (
		current  []T
		currSize int
	)
	for i := range items {
		// Start a new batch when this item would push the current one over, but
		// never emit an empty batch just because one item is oversized.
		if len(current) > 0 && currSize+sizes[i] > maxBytes {
			batches = append(batches, current)
			current = nil
			currSize = 0
		}
		current = append(current, items[i])
		currSize += sizes[i]
	}
	if len(current) > 0 {
		batches = append(batches, current)
	}
	return batches, oversized, nil
}

// ChunkMetaFor builds the ChunkMeta for batch index of a snapshot.
func ChunkMetaFor(snapshotID string, index, count, totalItems int) *ChunkMeta {
	return &ChunkMeta{
		SnapshotID: snapshotID,
		BatchIndex: index,
		BatchCount: count,
		TotalItems: totalItems,
	}
}
