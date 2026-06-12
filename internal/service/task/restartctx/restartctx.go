package restartctx

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Context records the task that triggered a planned agent restart or device
// reboot. Written to disk before os.Exit() so the restarted binary can mark
// the task as success instead of letting ResetInterruptedTasks mark it failed.
type Context struct {
	TaskID      string    `json:"task_id"`
	Reason      string    `json:"reason"`       // "agent-update" | "device-reboot"
	FromVersion string    `json:"from_version"` // populated for agent-update
	InitiatedAt time.Time `json:"initiated_at"`
}

// Write atomically writes rc to path via a temp file in the same directory.
func Write(path string, rc Context) error {
	data, err := json.Marshal(rc)
	if err != nil {
		return fmt.Errorf("marshal restart context: %w", err)
	}

	tmp := path + ".tmp"
	// #nosec G306 - file contains only task metadata, no secrets
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write restart context: %w", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename restart context: %w", err)
	}

	return nil
}

// ReadAndClear reads the context file at path, removes it, and returns the
// parsed Context. Returns nil, nil if the file does not exist (normal startup).
func ReadAndClear(path string) (*Context, error) {
	data, err := os.ReadFile(path) // #nosec G304 - path is a controlled internal path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read restart context: %w", err)
	}

	if removeErr := os.Remove(path); removeErr != nil {
		// Log-worthy but not fatal; proceed with the data we have.
		_ = removeErr
	}

	var rc Context
	if err := json.Unmarshal(data, &rc); err != nil {
		return nil, fmt.Errorf("parse restart context: %w", err)
	}

	return &rc, nil
}

// PathFor returns the canonical pending_restart.json path given the agent's
// config file path (e.g. /opt/sentinelgo/.sentinelgo/config.json).
func PathFor(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "pending_restart.json")
}
