package yara

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ErrInvalidTask is returned by DecodeTaskParams.
var ErrInvalidTask = errors.New("yara: invalid yara-scan params")

// TaskParams are the yara-scan native task's params (§4).
type TaskParams struct {
	// ScanID is a backend addition: the server's yara_scans row id, which
	// the agent uses as its scan id. Empty means the agent mints one.
	ScanID string `json:"scan_id,omitempty"`
	Preset string `json:"preset"`
	// Paths are this device's folders for a custom scan (empty for quick
	// and full).
	Paths []string `json:"paths"`
	// RulesetIDs nil means every ruleset in the bundle.
	RulesetIDs []string `json:"ruleset_ids"`
	Reason     string   `json:"reason"`
}

// Task result states. The task answers as soon as the scan has started (or
// couldn't); the scan's outcome arrives as a scan_summary event.
const (
	TaskStarted = "started" // the scan is running
	TaskBusy    = "busy"    // another on-demand scan is running; this one didn't start
)

// TaskResult is the yara-scan task's result (§4). State is TaskStarted,
// TaskBusy, or a scan end state when the scan finished before the answer.
type TaskResult struct {
	ScanID       string `json:"scan_id"`
	State        string `json:"state"`
	FilesScanned int64  `json:"files_scanned"`
	Matches      int64  `json:"matches"`
}

// DecodeTaskParams parses and checks yara-scan params. A custom scan needs
// paths; quick and full ignore any.
func DecodeTaskParams(raw []byte) (TaskParams, error) {
	var p TaskParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return TaskParams{}, fmt.Errorf("%w: %w", ErrInvalidTask, err)
	}
	switch {
	case !ValidPreset(p.Preset):
		return TaskParams{}, fmt.Errorf("%w: unknown preset %q", ErrInvalidTask, p.Preset)
	case p.ScanID != "" && !IsUUID(p.ScanID):
		return TaskParams{}, fmt.Errorf("%w: scan_id is not a UUID", ErrInvalidTask)
	case p.Preset == PresetCustom && len(p.Paths) == 0:
		return TaskParams{}, fmt.Errorf("%w: a custom scan needs paths", ErrInvalidTask)
	}
	for _, id := range p.RulesetIDs {
		if !IsUUID(id) {
			return TaskParams{}, fmt.Errorf("%w: ruleset id %q is not a UUID", ErrInvalidTask, id)
		}
	}
	if p.Preset != PresetCustom {
		p.Paths = nil
	}
	return p, nil
}
