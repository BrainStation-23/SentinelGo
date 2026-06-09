package collector

import (
	"context"
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
type CheckpointData map[string]interface{}

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
