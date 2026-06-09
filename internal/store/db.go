package store

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

// Open opens (or creates) a SQLite database at path with WAL mode and increased busy timeout.
// MaxOpenConns is set to 1 because SQLite only allows one concurrent writer; using a larger
// pool causes spurious SQLITE_BUSY errors even within the same process.
// All entity stores in this package should use this function instead of sql.Open directly.
func Open(path string) (*sql.DB, error) {
	// Increase busy timeout to 30 seconds for Windows CI environment
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(30000)&_pragma=journal_mode(WAL)")
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
