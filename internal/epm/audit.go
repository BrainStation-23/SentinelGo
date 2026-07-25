package epm

import (
	"fmt"
	"time"
)

// AuditEntry records a single elevation attempt (allowed or denied) for
// durable, offline-first audit logging.
type AuditEntry struct {
	RequestID  string
	UserID     string
	AppPath    string
	AppHash    string
	Decision   PolicyDecision
	PolicyID   string
	LaunchedAt time.Time
}

// AuditSink persists AuditEntry values. internal/store.EPMStore satisfies this
// interface, so internal/epm has no dependency on database/sql or SQLite —
// same duck-typing seam used for swsvc.Catalog in the software-sync handler.
type AuditSink interface {
	InsertAuditLog(entry AuditEntry) error
}

// Auditor writes elevation outcomes to an AuditSink.
type Auditor struct {
	sink AuditSink
}

// NewAuditor returns an Auditor that writes through sink.
func NewAuditor(sink AuditSink) *Auditor {
	return &Auditor{sink: sink}
}

// Log records entry via the underlying sink.
func (a *Auditor) Log(entry AuditEntry) error {
	if err := a.sink.InsertAuditLog(entry); err != nil {
		return fmt.Errorf("log elevation audit entry: %w", err)
	}
	return nil
}
