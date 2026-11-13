package logging

import "sync/atomic"

// LoggingStats holds counters for the logging pipeline.
// All fields are updated atomically and safe for concurrent access.
type LoggingStats struct {
	LogsCollected int64
	LogsStored    int64
	LogsUploaded  int64
	UploadErrors  int64
	// DroppedOutOfWindow counts rows dated outside the server's retention
	// window, which are never queued (#437).
	DroppedOutOfWindow int64
	// DroppedLowSeverity counts rows below high severity, which are never
	// queued (#484).
	DroppedLowSeverity int64
}

// statsCounter wraps atomic int64 counters for internal use.
type statsCounter struct {
	collected atomic.Int64
	stored    atomic.Int64
	uploaded  atomic.Int64
	errors    atomic.Int64
	dropped   atomic.Int64
	lowSev    atomic.Int64
}

func (s *statsCounter) addCollected(n int64)          { s.collected.Add(n) }
func (s *statsCounter) addStored(n int64)             { s.stored.Add(n) }
func (s *statsCounter) addUploaded(n int64)           { s.uploaded.Add(n) }
func (s *statsCounter) addErrors(n int64)             { s.errors.Add(n) }
func (s *statsCounter) addDroppedOutOfWindow(n int64) { s.dropped.Add(n) }
func (s *statsCounter) addDroppedLowSeverity(n int64) { s.lowSev.Add(n) }

func (s *statsCounter) snapshot() LoggingStats {
	return LoggingStats{
		LogsCollected:      s.collected.Load(),
		LogsStored:         s.stored.Load(),
		LogsUploaded:       s.uploaded.Load(),
		UploadErrors:       s.errors.Load(),
		DroppedOutOfWindow: s.dropped.Load(),
		DroppedLowSeverity: s.lowSev.Load(),
	}
}
