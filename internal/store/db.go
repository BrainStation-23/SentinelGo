package store

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

// Open opens (or creates) a SQLite database at path with WAL mode and a 5-second busy timeout.
// MaxOpenConns is set to 1 because SQLite only allows one concurrent writer; using a larger
// pool causes spurious SQLITE_BUSY errors even within the same process.
// All entity stores in this package should use this function instead of sql.Open directly.
//
// auto_vacuum=incremental lets freed pages be returned to the OS via PRAGMA
// incremental_vacuum, so a store that spikes then drains (e.g. the audit-log queue
// after an upload backlog) can shrink its file instead of holding the high-water mark
// forever. The pragma only takes effect when a new database is created; existing files
// keep auto_vacuum=NONE until a full VACUUM rewrites them (see AuditLogStore.Maintain).
func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=auto_vacuum(incremental)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

func formatTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func parseTime(data []byte) *time.Time {
	if len(data) == 0 {
		return nil
	}
	t, err := time.Parse(time.RFC3339, string(data))
	if err != nil {
		return nil
	}
	return &t
}
