package native

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"sentinelgo/internal/config"
	"sentinelgo/internal/taskstore"
	"sentinelgo/internal/yara"
)

// YARAScanner runs threat hunting scans (#414); the service installs it
// when YARA is on (scan.Runner).
type YARAScanner interface {
	// StartScan starts an on-demand scan and returns once it runs (or is
	// busy). An error means no scan started. ctx bounds only the start (a
	// first load of the cached rules), not the scan.
	StartScan(ctx context.Context, p yara.TaskParams) (yara.TaskResult, error)
	// CancelScan stops the running scan and returns its id ("" if none).
	CancelScan() string
}

var (
	yaraScannerMu sync.RWMutex
	yaraScanner   YARAScanner
)

// SetYARAScanner installs (or with nil removes) what yara-scan and
// yara-scan-cancel call.
func SetYARAScanner(s YARAScanner) {
	yaraScannerMu.Lock()
	defer yaraScannerMu.Unlock()
	yaraScanner = s
}

func currentYARAScanner() YARAScanner {
	yaraScannerMu.RLock()
	defer yaraScannerMu.RUnlock()
	return yaraScanner
}

// errYARAOff is the result when the agent runs no scans.
var errYARAOff = errors.New("threat hunting is not running on this device (yara_enabled is false in config.json, or the agent is stopping)")

// yaraScanHandler is the yara-scan task (contract §4): it validates the
// params, starts the scan and answers at once with {scan_id, state}. The
// scan's outcome arrives later as a scan_summary event, so a long scan
// doesn't hold the task open.
type yaraScanHandler struct{}

func init() { Register(&yaraScanHandler{}) }

func (h *yaraScanHandler) Slugs() []string { return []string{yara.TaskScan} }

func (h *yaraScanHandler) Run(ctx context.Context, _ *config.Config, task taskstore.Task) (string, error) {
	raw, err := json.Marshal(task.Payload)
	if err != nil {
		return "", fmt.Errorf("%s: %w", yara.TaskScan, err)
	}
	p, err := yara.DecodeTaskParams(raw)
	if err != nil {
		return "", err
	}
	s := currentYARAScanner()
	if s == nil {
		return "", errYARAOff
	}
	res, err := s.StartScan(ctx, p)
	if err != nil {
		return "", fmt.Errorf("%s: %w", yara.TaskScan, err)
	}
	msg := fmt.Sprintf("YARA %s scan %s started", p.Preset, res.ScanID)
	if res.State == yara.TaskBusy {
		msg = fmt.Sprintf("YARA scan not started: on-demand scan %s is still running", res.RunningScanID)
	}
	return resultNote(msg, res), nil
}

// resultNote is msg followed by the JSON result on its own last line, where
// the backend reads it (Compliance-OS docs/yara.md).
func resultNote(msg string, result any) string {
	data, err := json.Marshal(result)
	if err != nil {
		return msg
	}
	return msg + "\n" + string(data)
}

// yaraScanCancelHandler is yara-scan-cancel (no params): it stops the
// running scan, which sends a cancelled scan_summary. Nothing running is
// not an error (the scan may just have finished).
type yaraScanCancelHandler struct{}

func init() { Register(&yaraScanCancelHandler{}) }

func (h *yaraScanCancelHandler) Slugs() []string { return []string{yara.TaskScanCancel} }

func (h *yaraScanCancelHandler) Run(_ context.Context, _ *config.Config, _ taskstore.Task) (string, error) {
	idle := resultNote("No YARA scan was running", map[string]string{"state": "idle"})
	s := currentYARAScanner()
	if s == nil {
		return idle, nil
	}
	id := s.CancelScan()
	if id == "" {
		return idle, nil
	}
	return resultNote(fmt.Sprintf("YARA scan %s cancelled", id),
		map[string]string{"scan_id": id, "state": yara.ScanCancelled}), nil
}
