package logging

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"sentinelgo/internal/auditlogs/parser"
	"sentinelgo/internal/models"
	auditlogsvc "sentinelgo/internal/service/auditlog"
)

// Audit-log retention window (#437). The server keeps only the last few days
// of logs and says so in every enqueue response (Compliance-OS#828). The agent
// starts sources with no checkpoint at the window's start and never queues
// rows outside it, instead of shipping history the server deletes.
const (
	windowFile           = "audit_logs_window.json"
	defaultRetentionDays = 3
	maxRetentionDays     = 30             // ignore anything larger from the server
	futureSlack          = 24 * time.Hour // rows dated up to this far ahead are kept
)

// auditWindow is the latest window from the server, persisted next to the
// checkpoints. A nil *auditWindow uses the defaults, so tests that build a
// LoggingIntegration by hand need none.
type auditWindow struct {
	mu   sync.Mutex
	path string
	now  func() time.Time
	st   windowState
}

type windowState struct {
	RetentionDays     int       `json:"retention_days"`
	MaxEventDataBytes int       `json:"max_event_data_bytes,omitempty"`
	AcceptAfter       time.Time `json:"accept_after"`
	AcceptBefore      time.Time `json:"accept_before"`
}

// loadWindow reads the persisted window from dir, or starts from the defaults.
func loadWindow(dir string) *auditWindow {
	w := &auditWindow{
		path: filepath.Join(dir, windowFile),
		now:  time.Now,
		st:   windowState{RetentionDays: defaultRetentionDays},
	}
	raw, err := os.ReadFile(w.path)
	if err != nil {
		return w
	}
	var st windowState
	if err := json.Unmarshal(raw, &st); err != nil {
		log.Printf("[logging] warning: ignoring unreadable %s: %v", windowFile, err)
		return w
	}
	if validRetention(st.RetentionDays) {
		w.st = st
	}
	return w
}

func validRetention(days int) bool { return days >= 1 && days <= maxRetentionDays }

// retention is how far back the agent collects.
func (w *auditWindow) retention() time.Duration {
	days := defaultRetentionDays
	if w != nil {
		w.mu.Lock()
		days = w.st.RetentionDays
		w.mu.Unlock()
	}
	return time.Duration(days) * 24 * time.Hour
}

// maxEventDataBytes is the server's per-row event_data limit, 0 for the default.
func (w *auditWindow) maxEventDataBytes() int {
	if w == nil {
		return 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.st.MaxEventDataBytes
}

// bounds returns the accepted created_at range at this moment: the retention
// window and a day of clock skew ahead, narrowed by the server's own bounds
// while they are still current (a stale bound from an old response is
// ignored).
func (w *auditWindow) bounds() (after, before time.Time) {
	now := time.Now()
	st := windowState{RetentionDays: defaultRetentionDays}
	if w != nil {
		now = w.now()
		w.mu.Lock()
		st = w.st
		w.mu.Unlock()
	}
	after = now.Add(-time.Duration(st.RetentionDays) * 24 * time.Hour)
	before = now.Add(futureSlack)
	if st.AcceptAfter.After(after) && st.AcceptAfter.Before(now) {
		after = st.AcceptAfter
	}
	if st.AcceptBefore.After(now) && st.AcceptBefore.Before(before) {
		before = st.AcceptBefore
	}
	return after, before
}

// update stores the server's window and persists it when it changed.
func (w *auditWindow) update(sw *auditlogsvc.ServerWindow) {
	if w == nil || sw == nil {
		return
	}
	w.mu.Lock()
	st := w.st
	if validRetention(sw.RetentionDays) {
		st.RetentionDays = sw.RetentionDays
	}
	if sw.MaxEventDataBytes > 0 {
		st.MaxEventDataBytes = sw.MaxEventDataBytes
	}
	st.AcceptAfter, st.AcceptBefore = sw.AcceptAfter, sw.AcceptBefore
	changed := st.RetentionDays != w.st.RetentionDays || st.MaxEventDataBytes != w.st.MaxEventDataBytes
	w.st = st
	w.mu.Unlock()

	// accept_after/before move with every response, so only a new retention
	// or limit is worth a write; the bounds are re-read from each response.
	if !changed {
		return
	}
	log.Printf("[logging] server audit-log window: retention %d days, event_data limit %d bytes",
		st.RetentionDays, st.MaxEventDataBytes)
	raw, err := json.Marshal(st)
	if err != nil {
		return
	}
	// #nosec G306 - same permissions as checkpoints.json
	if err := os.WriteFile(w.path, raw, 0644); err != nil {
		log.Printf("[logging] warning: failed to save %s: %v", windowFile, err)
	}
}

// filter keeps the logs whose created_at is inside the window and returns how
// many it dropped. A row whose created_at can't be parsed is kept: the server
// decides.
func (w *auditWindow) filter(logs []models.AuditLog) ([]models.AuditLog, int) {
	after, before := w.bounds()
	kept := logs[:0]
	for _, l := range logs {
		ts, err := time.Parse(time.RFC3339, l.Timestamp)
		if err == nil && (ts.Before(after) || ts.After(before)) {
			continue
		}
		kept = append(kept, l)
	}
	return kept, len(logs) - len(kept)
}

// eventDataTarget is the size each row's event_data is trimmed to.
func (w *auditWindow) eventDataTarget() int {
	return parser.EventDataTarget(w.maxEventDataBytes())
}
