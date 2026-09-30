package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver used by sql.Open below
)

// Open opens (or creates) a SQLite database at path with WAL mode and a 5-second busy timeout.
// MaxOpenConns is set to 1 because SQLite only allows one concurrent writer; using a larger
// pool causes spurious SQLITE_BUSY errors even within the same process.
// All entity stores in this package should use this function instead of sql.Open directly.
func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
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

// deleteNotIn removes rows from table for agentID whose (name, source) key is
// not in activeKeys. activeKeys entries are "<name>\x00<source>". table is
// always a package-internal literal ("services" or "software"), never
// external input, so it is safe to interpolate directly.
func deleteNotIn(db *sql.DB, table, agentID string, activeKeys []string) error {
	if len(activeKeys) == 0 {
		// #nosec G201 - table is always a package-internal literal ("services" or "software"), never external input
		_, err := db.Exec(fmt.Sprintf("DELETE FROM %s WHERE agent_id = ?", table), agentID)
		return err
	}

	placeholders := make([]string, len(activeKeys))
	args := make([]any, 0, len(activeKeys)+1)
	args = append(args, agentID)
	for i, k := range activeKeys {
		placeholders[i] = "?"
		args = append(args, k)
	}

	// #nosec G201,G202 - table is always a package-internal literal ("services" or "software"), never external input;
	// only the placeholder count is dynamic, every value is passed as a parameterized arg below.
	query := fmt.Sprintf("DELETE FROM %s WHERE agent_id = ? AND (name || char(0) || source) NOT IN (", table) +
		strings.Join(placeholders, ",") + ")"
	_, err := db.Exec(query, args...)
	return err
}
