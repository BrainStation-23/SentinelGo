//go:build !windows && !linux && !darwin

package collector

import (
	"context"
	"log"
	"runtime"
)

// stubCollector is a no-op collector for platforms without a real implementation.
// Unlike a silent no-op, it logs a clear warning on creation so that "no audit
// logs" is never mistaken for "everything is fine" on an unsupported OS.
type stubCollector struct{}

// NewCollector returns a no-op collector on unsupported platforms and logs a
// warning making the lack of audit log collection explicit.
func NewCollector() Collector {
	log.Printf("[collector] WARNING: audit log collection is not supported on %s; "+
		"no audit logs will be collected on this platform", runtime.GOOS)
	return &stubCollector{}
}

// Collect is a no-op on unsupported platforms and returns the checkpoint unchanged.
func (s *stubCollector) Collect(_ context.Context, checkpoint CheckpointData) ([]RawLogEntry, CheckpointData, error) {
	return nil, checkpoint, nil
}

// Subscribe is a no-op on unsupported platforms.
func (s *stubCollector) Subscribe(_ context.Context, _ chan<- RawLogEntry) error {
	return nil
}

// Sources returns nil on unsupported platforms.
func (s *stubCollector) Sources() []string {
	return nil
}
