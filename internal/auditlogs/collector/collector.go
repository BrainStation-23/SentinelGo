package collector

import (
	"context"
	"encoding/json"
	"strconv"
	"time"
)

// RawLogEntry represents a single log entry from an OS-specific source
// before normalization into the AuditLog model.
type RawLogEntry struct {
	Timestamp  time.Time
	Source     string // e.g. "windows_security", "journal", "auth.log"
	EventID    string // OS-specific event ID (e.g. "4624" on Windows)
	RawMessage string
	Severity   string            // OS-native severity before normalization
	Metadata   map[string]string // Additional key-value pairs extracted from the event
}

// CheckpointData holds per-source checkpoint values.
// Keys are source names, values are source-specific position markers
// (Event Record ID, journal cursor, file offset, timestamp, etc.).
//
// A checkpoint map round-trips through two different paths between collection
// cycles: in-memory (where numeric values keep their original Go type, e.g.
// int64) and JSON persistence (where every number decodes back as float64).
// Readers MUST therefore use the tolerant CheckpointInt64/CheckpointFloat64
// accessors rather than a bare type assertion — a bare `v.(float64)` panics
// when the value is still an in-memory int64, which previously crashed the
// agent on the cycle after any events were collected.
type CheckpointData map[string]interface{}

// CheckpointInt64 returns the checkpoint value for key as an int64, accepting
// any numeric representation the value may carry (int64, float64, int, json.Number,
// or a numeric string). ok is false when the key is absent or not numeric.
func CheckpointInt64(cp CheckpointData, key string) (val int64, ok bool) {
	v, present := cp[key]
	if !present {
		return 0, false
	}
	switch n := v.(type) {
	case int64:
		return n, true
	case float64:
		return int64(n), true
	case int:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case string:
		i, err := strconv.ParseInt(n, 10, 64)
		return i, err == nil
	default:
		return 0, false
	}
}

// CheckpointFloat64 returns the checkpoint value for key as a float64, accepting
// any numeric representation (float64, int64, int, json.Number, or a numeric
// string). ok is false when the key is absent or not numeric.
func CheckpointFloat64(cp CheckpointData, key string) (val float64, ok bool) {
	v, present := cp[key]
	if !present {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return n, true
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(n, 64)
		return f, err == nil
	default:
		return 0, false
	}
}

// Collector defines the interface for OS-specific log collection.
// Each platform implements this behind build tags.
type Collector interface {
	// Collect performs a batch query from the given checkpoint position.
	// Returns collected entries and an updated checkpoint reflecting the new position.
	Collect(ctx context.Context, checkpoint CheckpointData) ([]RawLogEntry, CheckpointData, error)

	// Subscribe starts real-time streaming of critical events to the channel.
	// Blocks until ctx is cancelled. Implementations that don't support
	// real-time subscription return nil immediately.
	Subscribe(ctx context.Context, ch chan<- RawLogEntry) error

	// Sources returns the list of log source names this collector handles.
	Sources() []string
}
