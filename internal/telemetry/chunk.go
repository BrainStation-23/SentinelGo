package telemetry

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

// MaxPayloadBytes is the ceiling for a single enqueued message. The backend's
// enqueue limit is 1 MB; this leaves headroom for the envelope wrapper.
//
// The value matches the constant the audit-log uploader already applies. It is
// restated here rather than imported so the telemetry layer stays independent
// of the logging package.
const MaxPayloadBytes = 900_000

// envelopeOverheadMargin is reserved on top of the measured envelope overhead
// when computing a chunk budget, covering the section name, chunk block and
// JSON punctuation that only exist once items are present.
const envelopeOverheadMargin = 4096

// ErrNotChunkable is returned when a section marked Chunked does not carry a
// list payload.
var ErrNotChunkable = errors.New("telemetry: chunked section payload is not a slice")

// ChunkMeta describes one batch of a chunked, high-cardinality section.
//
// Chunking rather than truncating is deliberate: a truncated process or
// certificate list is indistinguishable from a genuinely short one, so silently
// dropping the tail would misreport the endpoint. Splitting preserves the whole
// set and lets the backend reassemble it.
type ChunkMeta struct {
	// SnapshotID ties every batch of one logical snapshot together. It is
	// generated once per snapshot and persisted with the queued message, so a
	// delivery retry reuses it rather than creating a second logical snapshot.
	SnapshotID string `json:"snapshot_id"`
	// BatchIndex is 0-based.
	BatchIndex int `json:"batch_index"`
	BatchCount int `json:"batch_count"`
	// TotalItems is the true item count before batching, so the backend can
	// verify completeness and detect a lost batch.
	TotalItems int `json:"total_items"`
	// Truncated marks a snapshot the agent could not send in full — set only
	// when an individual item exceeds the size limit on its own and therefore
	// cannot be placed in any batch. It is a last resort, always logged and
	// surfaced in telemetry health, never a silent drop.
	Truncated bool `json:"truncated,omitempty"`
	// ExcludedItems is how many items were dropped for that reason.
	//
	// TotalItems minus ExcludedItems is what the backend should expect to
	// receive across all batches, so a reassembled snapshot can be reconciled
	// exactly rather than merely flagged as incomplete.
	ExcludedItems int `json:"excluded_items,omitempty"`
}

// NewSnapshotID returns a random identifier for one logical snapshot.
func NewSnapshotID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is not recoverable here; fall back to a value that
		// still groups batches within one process run.
		return hex.EncodeToString([]byte(fmt.Sprintf("snapshot-%d", len(b))))
	}
	return hex.EncodeToString(b[:])
}

// Chunk splits items into batches whose encoded JSON stays within maxBytes.
//
// Each item is measured once and items are packed greedily in order, so a
// caller that sorted its list keeps that order across batches.
//
// An item whose own encoding exceeds maxBytes cannot be placed in any batch
// that respects the limit. Such items are EXCLUDED and their indices returned,
// because emitting them would guarantee a rejected payload and lose the whole
// batch rather than the one item. The caller must mark the snapshot truncated
// and report the loss — see ChunkSection.
func Chunk[T any](items []T, maxBytes int) (batches [][]T, oversized []int, err error) {
	if len(items) == 0 {
		return nil, nil, nil
	}
	if maxBytes <= 0 {
		maxBytes = MaxPayloadBytes
	}

	sizes := make([]int, len(items))
	for i := range items {
		buf, mErr := json.Marshal(items[i])
		if mErr != nil {
			return nil, nil, fmt.Errorf("chunk: marshal item %d: %w", i, mErr)
		}
		// +1 for the separating comma in the encoded array.
		sizes[i] = len(buf) + 1
		if sizes[i] > maxBytes {
			oversized = append(oversized, i)
		}
	}

	skip := make(map[int]bool, len(oversized))
	for _, i := range oversized {
		skip[i] = true
	}

	var (
		current  []T
		currSize int
	)
	for i := range items {
		if skip[i] {
			continue
		}
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

// ChunkSection splits a chunked section's payload into batches.
//
// The payload arrives as `any` because sections are collector-defined, so the
// slice is walked reflectively. Behaviour otherwise matches Chunk: order is
// preserved, and items too large to fit any batch are excluded and reported so
// the caller can mark the snapshot truncated.
//
// totalItems is the count BEFORE exclusion, so the backend always learns the
// true size of the set even when part of it could not be sent.
func ChunkSection(payload any, maxBytes int) (batches [][]any, totalItems int, oversized []int, err error) {
	if payload == nil {
		return nil, 0, nil, nil
	}

	rv := reflect.ValueOf(payload)
	for rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return nil, 0, nil, nil
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return nil, 0, nil, fmt.Errorf("%w (got %T)", ErrNotChunkable, payload)
	}

	totalItems = rv.Len()
	items := make([]any, 0, totalItems)
	for i := 0; i < totalItems; i++ {
		items = append(items, rv.Index(i).Interface())
	}

	batches, oversized, err = Chunk(items, maxBytes)
	return batches, totalItems, oversized, err
}

// ChunkMetaFor builds the ChunkMeta for one batch of a snapshot.
//
// excluded is the number of items that could not be sent at all; it implies
// Truncated, so the two can never disagree.
func ChunkMetaFor(snapshotID string, index, count, totalItems, excluded int) *ChunkMeta {
	return &ChunkMeta{
		SnapshotID:    snapshotID,
		BatchIndex:    index,
		BatchCount:    count,
		TotalItems:    totalItems,
		Truncated:     excluded > 0,
		ExcludedItems: excluded,
	}
}
