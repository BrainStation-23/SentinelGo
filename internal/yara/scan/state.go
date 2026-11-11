package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"sentinelgo/internal/winsec"
	"sentinelgo/internal/yara"
	"sentinelgo/internal/yara/report"
	"sentinelgo/internal/yara/walk"
)

// StateFileName is the scan state's file, next to config.json: per schedule
// when it last ran and where a stopped scan resumes. It is owner-only.
const StateFileName = "yara_scan_state.json"

// SkipCacheFileName is the skip cache (#413), next to config.json.
const SkipCacheFileName = "yara_skip.cache"

// state is what survives a restart.
type state struct {
	Schedules map[string]*schedState `json:"schedules"`
	// LastScan is the last finished scan (any trigger), for the status and
	// `sentinelgo yara status`.
	LastScan *yara.ScanSummary `json:"last_scan,omitempty"`
}

// schedState is one schedule on this device.
type schedState struct {
	// Seen is when the agent first saw the schedule.
	Seen time.Time `json:"seen"`
	// LastRun is when its last scan ended (completed, partial, cancelled or
	// failed). A scan the service stopped doesn't count.
	LastRun time.Time `json:"last_run,omitzero"`
	Resume  *resume   `json:"resume,omitempty"`
}

// resume is where the schedule's next scan starts.
type resume struct {
	// RulesKey is the ruleset set the position was reached with; with other
	// rules the scan starts over.
	RulesKey   string          `json:"rules_key"`
	Checkpoint walk.Checkpoint `json:"checkpoint"`
	// Scan is set when the service stopped (or an on-demand scan preempted)
	// the scan: it continues under the same id and counts, and its summary
	// is sent only when it ends. Without it, a partial scan ended and the
	// next one starts from the position.
	Scan *interrupted `json:"scan,omitempty"`
}

// interrupted is a stopped scan's identity and counts so far.
type interrupted struct {
	ScanID    string          `json:"scan_id"`
	Started   time.Time       `json:"started"`
	Scanned   int64           `json:"scanned"`
	Skipped   int64           `json:"skipped"`
	Errors    int64           `json:"errors"`
	TCCDenied bool            `json:"tcc_denied,omitempty"`
	Progress  report.Progress `json:"progress"`
}

// loadState reads path; a missing or unreadable file is an empty state (an
// unreadable one is logged by the caller through the error).
func loadState(path string) (*state, error) {
	st := &state{Schedules: map[string]*schedState{}}
	if path == "" {
		return st, nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- the agent's own state file
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("read YARA scan state: %w", err)
	}
	if err := json.Unmarshal(data, st); err != nil {
		return &state{Schedules: map[string]*schedState{}}, fmt.Errorf("YARA scan state %s unreadable, starting empty: %w", path, err)
	}
	if st.Schedules == nil {
		st.Schedules = map[string]*schedState{}
	}
	return st, nil
}

// save writes the state atomically, owner-only.
func (st *state) save(path string) error {
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(path, data); err != nil {
		return fmt.Errorf("save YARA scan state: %w", err)
	}
	return nil
}

// writeFileAtomic replaces path with data, owner-only.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".yara-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	_ = winsec.SecurePath(path)
	return nil
}

// LastScan reads the last finished scan from the state file at path (for
// `sentinelgo yara status`); nil when there is none.
func LastScan(path string) (*yara.ScanSummary, error) {
	st, err := loadState(path)
	return st.LastScan, err
}

// StatusFileName is the service's threat hunting status, next to
// config.json, for `sentinelgo yara status`. Like the status sent to the
// server it names rules and rulesets, never rule text.
const StatusFileName = "yara_status.json"

// LocalStatus is what StatusFileName holds.
type LocalStatus struct {
	UpdatedAt time.Time `json:"updated_at"`
	// LocalEnabled is config.json's yara_enabled.
	LocalEnabled bool        `json:"local_enabled"`
	Status       yara.Status `json:"status"`
	// Workers is the scan worker pool's health (nil when none runs).
	Workers      *Workers         `json:"workers,omitempty"`
	Scanning     *Running         `json:"scanning,omitempty"`
	Schedules    []ScheduleStatus `json:"schedules,omitempty"`
	QueuedEvents int              `json:"queued_events"`
	// DroppedEvents were dropped over the offline queue's cap.
	DroppedEvents int64 `json:"dropped_events"`
}

// Workers is the scan worker pool's health.
type Workers struct {
	Live     int    `json:"live"`
	Sandbox  string `json:"sandbox,omitempty"`
	Failures int    `json:"failures"`
	Disabled bool   `json:"disabled,omitempty"`
}

// ScheduleStatus is one bundle schedule on this device.
type ScheduleStatus struct {
	ID         string    `json:"id"`
	Preset     string    `json:"preset"`
	EveryHours int       `json:"every_hours"`
	LastRun    time.Time `json:"last_run,omitzero"`
	NextRun    time.Time `json:"next_run,omitzero"`
	// Resumes says the next scan continues a stopped or partial one.
	Resumes bool `json:"resumes,omitempty"`
}

// WriteStatus saves ls at path, owner-only.
func WriteStatus(path string, ls LocalStatus) error {
	data, err := json.MarshalIndent(ls, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

// ReadStatus reads the status the service last wrote at path.
func ReadStatus(path string) (*LocalStatus, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the agent's own status file
	if err != nil {
		return nil, err
	}
	var ls LocalStatus
	if err := json.Unmarshal(data, &ls); err != nil {
		return nil, fmt.Errorf("YARA status %s unreadable: %w", path, err)
	}
	return &ls, nil
}
