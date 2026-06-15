// Package emergencylog records rare, terminal/transition failures — the things
// that should never happen (a failed self-update, a rejected agent login, a sync
// that keeps failing) — to a durable plain-text file for postmortem.
//
// It is deliberately NOT a general logger: callers reach for it only on emergency
// events, so the file stays tiny and signal-rich. All routine diagnostics still go
// to the standard log. Every emergency is also echoed to the standard log so it
// appears in the live service output (journald / Event Log / launchd) and is never
// lost even when the file could not be written.
//
// The package imports nothing from internal/ except the stdlib-only sanitize leaf,
// so any package may import it without risking an import cycle. It is a process
// global (like the stdlib log) because there is exactly one emergency log per agent.
package emergencylog

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"sentinelgo/internal/sanitize"
)

// retainDays is how many distinct daily files to keep (today + previous 2).
const retainDays = 3

var (
	mu      sync.Mutex
	dir     string // "" => not initialized => Record echoes to standard log only
	lastDay string // last UTC date a prune ran for, so prune runs once per day
)

// Init points the emergency log at dir (the agent's runtime directory) and prunes
// stale daily files. It is idempotent and meant to be called once at startup.
// It returns an error only if the directory cannot be created; callers should
// log-and-continue rather than treat this as fatal — Record degrades to echoing
// to the standard log when the package is uninitialized.
func Init(d string) error {
	mu.Lock()
	defer mu.Unlock()

	if err := os.MkdirAll(d, 0o750); err != nil {
		return fmt.Errorf("emergencylog: create dir %s: %w", d, err)
	}
	dir = d
	now := time.Now().UTC()
	prune(now)
	lastDay = now.Format("2006-01-02")
	return nil
}

// Record appends one emergency line to the current day's file. It is safe to call
// before Init (the event is echoed to the standard log only), safe to call from
// multiple goroutines, and never panics. category is a short, stable tag for
// grepping (e.g. "update", "auth", "sync", "startup").
func Record(category, format string, args ...any) {
	msg := sanitize.ForLog(fmt.Sprintf(format, args...))

	// Always echo so the event reaches the live service log and is never lost,
	// even if Init failed or the file write below fails.
	log.Printf("EMERGENCY [%s] %s", category, msg)

	mu.Lock()
	defer mu.Unlock()

	if dir == "" {
		return
	}

	now := time.Now().UTC()
	day := now.Format("2006-01-02")
	if day != lastDay {
		prune(now)
		lastDay = day
	}

	line := fmt.Sprintf("%s EMERGENCY [%s] %s\n", now.Format(time.RFC3339), category, msg)
	path := filepath.Join(dir, "emergency-"+day+".log")

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) //nolint:gosec // diagnostics file, readable by operators; carries no secrets
	if err != nil {
		log.Printf("emergencylog: write failed: %v", err)
		return
	}
	defer func() { _ = f.Close() }()

	if _, err := f.WriteString(line); err != nil {
		log.Printf("emergencylog: write failed: %v", err)
	}
}

// prune removes emergency-*.log files whose date is older than the retention
// window. It must be called with mu held. Failures are best-effort and silent —
// a missing or unreadable directory simply leaves files in place.
func prune(now time.Time) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	// Keep retainDays distinct dates ending today: cutoff is the oldest date kept.
	cutoff := now.AddDate(0, 0, -(retainDays - 1)).Truncate(24 * time.Hour)
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "emergency-") || !strings.HasSuffix(name, ".log") {
			continue
		}
		datePart := strings.TrimSuffix(strings.TrimPrefix(name, "emergency-"), ".log")
		d, perr := time.Parse("2006-01-02", datePart)
		if perr != nil {
			continue
		}
		if d.Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}
