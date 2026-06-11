package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"sentinelgo/internal/taskstore"
)

const tasksSchemaV1 = `
CREATE TABLE IF NOT EXISTS tasks (
	id TEXT PRIMARY KEY,
	command_id TEXT,
	slug TEXT,
	name TEXT,
	description TEXT,
	category TEXT,
	tags TEXT,
	payload TEXT,
	scripts TEXT,
	status TEXT,
	note TEXT,
	assigned_at TEXT,
	completed_at TEXT,
	created_at TEXT,
	updated_at TEXT,
	created_by TEXT,
	is_synced INTEGER DEFAULT 0,
	stored_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_assigned_at ON tasks(assigned_at);
`

// maxRetryAttempts is the maximum number of times a failed task is reset to
// 'assigned' before it is abandoned. Prevents permanently-failing tasks from
// looping forever.
const maxRetryAttempts = 3

var tasksMigrations = []Migration{
	{Version: 1, SQL: tasksSchemaV1},
	// Fix existing tasks with empty status so the executor can pick them up.
	{Version: 2, SQL: "UPDATE tasks SET status = 'assigned' WHERE status = '' OR status IS NULL"},
	// Track how many times a task has been retried so we can cap retries.
	{Version: 3, SQL: "ALTER TABLE tasks ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0"},
}

// TaskStore is a SQLite-backed queue for agent tasks.
type TaskStore struct {
	db     *sql.DB
	dbPath string
}

// NewTaskStore opens (or creates) the SQLite database at dbPath and runs schema migrations.
func NewTaskStore(dbPath string) (*TaskStore, error) {
	db, err := Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open task store: %w", err)
	}

	if err := Migrate(db, tasksMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate task store: %w", err)
	}

	return &TaskStore{db: db, dbPath: dbPath}, nil
}

// StoreTasks inserts or replaces tasks from an agent_get_tasks response.
func (s *TaskStore) StoreTasks(tasks []taskstore.Task) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			log.Printf("TaskStore: rollback: %v", err)
		}
	}()

	// INSERT OR IGNORE: skip tasks already present in the DB regardless of
	// status. OR REPLACE would reset a completed/running task back to
	// 'assigned', causing it to be executed again.
	stmt, err := tx.Prepare(`
		INSERT OR IGNORE INTO tasks
		(id, command_id, slug, name, description, category, tags, payload, scripts,
		 status, note, assigned_at, completed_at, created_at, updated_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer func() {
		if err := stmt.Close(); err != nil {
			log.Printf("TaskStore: close stmt: %v", err)
		}
	}()

	for _, t := range tasks {
		tagsJSON, _ := json.Marshal(t.Tags)
		payloadJSON, _ := json.Marshal(t.Payload)
		scriptsJSON, _ := json.Marshal(t.Scripts)

		if t.Status == "" {
			t.Status = "assigned"
		}

		_, err := stmt.Exec(
			t.ID, t.CommandID, t.Slug, t.Name, t.Description, t.Category,
			string(tagsJSON), string(payloadJSON), string(scriptsJSON),
			t.Status, t.Note, formatTime(t.AssignedAt), formatTime(t.CompletedAt),
			formatTime(t.CreatedAt), formatTime(t.UpdatedAt), t.CreatedBy,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// ResetOldFailedTasks resets failed tasks older than cooldown back to 'assigned'
// for retry, up to maxRetryAttempts times. Tasks that have already been retried
// the maximum number of times are left in 'failed' state permanently.
func (s *TaskStore) ResetOldFailedTasks(cooldown time.Duration) (int, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	cutoff := time.Now().UTC().Add(-cooldown).Format(time.RFC3339)

	result, err := s.db.Exec(`
		UPDATE tasks
		SET status = 'assigned', note = '', completed_at = NULL, updated_at = ?,
		    attempt_count = attempt_count + 1
		WHERE status = 'failed'
		AND attempt_count < ?
		AND completed_at IS NOT NULL
		AND completed_at < ?
	`, now, maxRetryAttempts, cutoff)
	if err != nil {
		return 0, err
	}

	rowsAffected, _ := result.RowsAffected()
	return int(rowsAffected), nil
}

// GetAssignedTasks returns all tasks with status 'assigned'.
func (s *TaskStore) GetAssignedTasks() ([]taskstore.Task, error) {
	log.Printf("TaskStore: querying assigned tasks from %s", s.dbPath)

	var totalCount int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM tasks").Scan(&totalCount)
	if totalCount == 0 {
		log.Printf("TaskStore: tasks table is empty")
	} else {
		log.Printf("TaskStore: %d total tasks in DB", totalCount)
		rowsStatus, err := s.db.Query("SELECT status, COUNT(*) FROM tasks GROUP BY status")
		if err == nil {
			defer func() {
				if err := rowsStatus.Close(); err != nil {
					log.Printf("TaskStore: close status rows: %v", err)
				}
			}()
			for rowsStatus.Next() {
				var status string
				var count int
				if err := rowsStatus.Scan(&status, &count); err == nil {
					log.Printf("TaskStore: status [%s]: %d tasks", status, count)
				}
			}
		}
	}

	rows, err := s.db.Query(`
		SELECT id, command_id, slug, name, description, category, tags, payload, scripts,
		       status, note, assigned_at, completed_at, created_at, updated_at, created_by
		FROM tasks
		WHERE status = 'assigned'
		ORDER BY assigned_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("TaskStore: close rows: %v", err)
		}
	}()

	return s.scanTasks(rows)
}

// MarkTaskExecuting transitions a task from 'assigned' to 'executing' before
// the script is invoked. This ensures that if the agent is killed mid-execution
// (e.g. by the reboot script it is running), the task is NOT picked up again on
// the next startup — GetAssignedTasks only returns WHERE status = 'assigned'.
func (s *TaskStore) MarkTaskExecuting(taskID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`
		UPDATE tasks SET status = 'executing', updated_at = ? WHERE id = ?
	`, now, taskID)
	return err
}

// ResetInterruptedTasks marks any task stuck in 'executing' (agent was killed
// mid-run) as 'failed' so it is reported to the server rather than silently
// re-executed. attempt_count is set to maxRetryAttempts so ResetOldFailedTasks
// never automatically recycles these back to 'assigned'.
// Called once per startup, before polling or execution.
func (s *TaskStore) ResetInterruptedTasks() (int, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := s.db.Exec(`
		UPDATE tasks
		SET status       = 'failed',
		    note         = 'Agent restarted during task execution; task may have completed. Re-check manually.',
		    completed_at = ?,
		    updated_at   = ?,
		    is_synced    = 0,
		    attempt_count = ?
		WHERE status = 'executing'
	`, now, now, maxRetryAttempts)
	if err != nil {
		return 0, err
	}
	n, _ := result.RowsAffected()
	return int(n), nil
}

// UpdateTaskStatus updates the status, note, and sync flag for a task.
func (s *TaskStore) UpdateTaskStatus(taskID, status, note string, isSynced bool) error {
	syncedValue := 0
	if isSynced {
		syncedValue = 1
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`
		UPDATE tasks
		SET status = ?, note = COALESCE(?, note), is_synced = ?, updated_at = ?,
		    completed_at = CASE WHEN ? IN ('success', 'failed') THEN ? ELSE completed_at END
		WHERE id = ?
	`, status, note, syncedValue, now, status, now, taskID)
	return err
}

// ClearCompletedTasks removes tasks completed before olderThan.
func (s *TaskStore) ClearCompletedTasks(olderThan time.Time) error {
	_, err := s.db.Exec(`
		DELETE FROM tasks
		WHERE status IN ('success', 'failed')
		AND completed_at IS NOT NULL
		AND completed_at < ?
	`, olderThan.UTC().Format(time.RFC3339))
	return err
}

// GetUnsyncedTasks returns completed tasks not yet reported to the server.
func (s *TaskStore) GetUnsyncedTasks() ([]taskstore.Task, error) {
	rows, err := s.db.Query(`
		SELECT id, command_id, slug, name, description, category, tags, payload, scripts,
		       status, note, assigned_at, completed_at, created_at, updated_at, created_by
		FROM tasks
		WHERE is_synced = 0 AND status IN ('success', 'failed', 'retrying')
	`)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("TaskStore: close unsynced rows: %v", err)
		}
	}()

	return s.scanTasks(rows)
}

// MarkTaskSynced marks a task as successfully reported to the server.
func (s *TaskStore) MarkTaskSynced(taskID string) error {
	_, err := s.db.Exec("UPDATE tasks SET is_synced = 1 WHERE id = ?", taskID)
	return err
}

// ShowTasks prints all tasks in the database to stdout.
func (s *TaskStore) ShowTasks() error {
	rows, err := s.db.Query(`
		SELECT id, command_id, slug, name, status, note, assigned_at, completed_at, stored_at
		FROM tasks
		ORDER BY stored_at DESC
	`)
	if err != nil {
		return err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("TaskStore: close show rows: %v", err)
		}
	}()

	fmt.Println("Tasks in SQLite database:")
	fmt.Println("==================================================================================")
	fmt.Printf("%-36s %-20s %-10s %-20s %-19s\n", "Task ID", "Command ID", "Status", "Name", "Assigned At")
	fmt.Println("----------------------------------------------------------------------------------")

	for rows.Next() {
		var id, commandID, slug, name, status, note string
		var assignedAt, completedAt, storedAt []byte

		if err := rows.Scan(&id, &commandID, &slug, &name, &status, &note, &assignedAt, &completedAt, &storedAt); err != nil {
			return err
		}

		assignedStr := string(assignedAt)
		if assignedStr == "" {
			assignedStr = "N/A"
		}

		fmt.Printf("%-36s %-20s %-10s %-20s %-19s\n",
			truncateString(id, 36),
			truncateString(commandID, 20),
			status,
			truncateString(name, 20),
			assignedStr[:min(19, len(assignedStr))])
	}

	return rows.Err()
}

// Close closes the database connection.
func (s *TaskStore) Close() error {
	return s.db.Close()
}

func (s *TaskStore) scanTasks(rows *sql.Rows) ([]taskstore.Task, error) {
	var tasks []taskstore.Task
	for rows.Next() {
		var t taskstore.Task
		var tagsJSON, payloadJSON, scriptsJSON []byte
		var assignedAt, completedAt, createdAt, updatedAt []byte

		err := rows.Scan(
			&t.ID, &t.CommandID, &t.Slug, &t.Name, &t.Description, &t.Category,
			&tagsJSON, &payloadJSON, &scriptsJSON,
			&t.Status, &t.Note, &assignedAt, &completedAt, &createdAt, &updatedAt, &t.CreatedBy,
		)
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal(tagsJSON, &t.Tags); err != nil {
			log.Printf("TaskStore: unmarshal tags: %v", err)
		}
		if err := json.Unmarshal(payloadJSON, &t.Payload); err != nil {
			log.Printf("TaskStore: unmarshal payload: %v", err)
		}
		if err := json.Unmarshal(scriptsJSON, &t.Scripts); err != nil {
			log.Printf("TaskStore: unmarshal scripts: %v", err)
		}
		t.AssignedAt = parseTime(assignedAt)
		t.CompletedAt = parseTime(completedAt)
		t.CreatedAt = parseTime(createdAt)
		t.UpdatedAt = parseTime(updatedAt)

		tasks = append(tasks, t)
	}

	if len(tasks) == 0 {
		return []taskstore.Task{}, nil
	}
	return tasks, rows.Err()
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
