package native

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"sentinelgo/internal/taskstore"
	"sentinelgo/internal/yara"
)

type fakeYARAScanner struct {
	got     []yara.TaskParams
	result  yara.TaskResult
	err     error
	running string
}

func (f *fakeYARAScanner) StartScan(_ context.Context, p yara.TaskParams) (yara.TaskResult, error) {
	f.got = append(f.got, p)
	return f.result, f.err
}

func (f *fakeYARAScanner) CancelScan() string {
	id := f.running
	f.running = ""
	return id
}

func withYARAScanner(t *testing.T, s YARAScanner) {
	t.Helper()
	SetYARAScanner(s)
	t.Cleanup(func() { SetYARAScanner(nil) })
}

// lastJSON parses the note's last line, as the backend does.
func lastJSON(t *testing.T, note string) map[string]any {
	t.Helper()
	lines := strings.Split(note, "\n")
	var out map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &out); err != nil {
		t.Fatalf("note %q: last line isn't JSON: %v", note, err)
	}
	return out
}

func TestYARAScan_Registered(t *testing.T) {
	for _, slug := range []string{"yara-scan", "yara-scan-cancel"} {
		if Find(slug) == nil {
			t.Errorf("%s not registered", slug)
		}
	}
}

func TestYARAScan_Started(t *testing.T) {
	id := yara.NewID()
	f := &fakeYARAScanner{result: yara.TaskResult{ScanID: id, State: yara.TaskStarted}}
	withYARAScanner(t, f)
	note, err := Find("yara-scan").Run(context.Background(), nil, taskstore.Task{Payload: map[string]any{
		"scan_id": id, "preset": "quick", "paths": []any{}, "ruleset_ids": nil, "reason": "incident 42"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := lastJSON(t, note); got["scan_id"] != id || got["state"] != "started" {
		t.Fatalf("result %v", got)
	}
	if len(f.got) != 1 || f.got[0].Preset != "quick" || f.got[0].RulesetIDs != nil || f.got[0].ScanID != id {
		t.Fatalf("params %+v", f.got)
	}
}

func TestYARAScan_Busy(t *testing.T) {
	running := yara.NewID()
	f := &fakeYARAScanner{result: yara.TaskResult{ScanID: yara.NewID(), State: yara.TaskBusy, RunningScanID: running}}
	withYARAScanner(t, f)
	note, err := Find("yara-scan").Run(context.Background(), nil, taskstore.Task{Payload: map[string]any{"preset": "full"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := lastJSON(t, note); got["state"] != "busy" || got["running_scan_id"] != running {
		t.Fatalf("result %v", got)
	}
}

// Invalid params fail the task before the scanner is called.
func TestYARAScan_InvalidParams(t *testing.T) {
	f := &fakeYARAScanner{}
	withYARAScanner(t, f)
	for _, p := range []map[string]any{
		{"preset": "everything"},
		{"preset": "custom"},
		{"preset": "quick", "ruleset_ids": []any{"not-a-uuid"}},
		{"preset": "quick", "scan_id": "nope"},
	} {
		if _, err := Find("yara-scan").Run(context.Background(), nil, taskstore.Task{Payload: p}); !errors.Is(err, yara.ErrInvalidTask) {
			t.Errorf("%v: err %v", p, err)
		}
	}
	if len(f.got) != 0 {
		t.Fatalf("scanner called with %+v", f.got)
	}
}

func TestYARAScan_ScannerRefuses(t *testing.T) {
	withYARAScanner(t, &fakeYARAScanner{err: errors.New("nothing to scan")})
	_, err := Find("yara-scan").Run(context.Background(), nil, taskstore.Task{Payload: map[string]any{"preset": "custom", "paths": []any{"/nope"}}})
	if err == nil || !strings.Contains(err.Error(), "nothing to scan") {
		t.Fatalf("err %v", err)
	}
}

func TestYARAScan_Off(t *testing.T) {
	SetYARAScanner(nil)
	if _, err := Find("yara-scan").Run(context.Background(), nil, taskstore.Task{Payload: map[string]any{"preset": "quick"}}); !errors.Is(err, errYARAOff) {
		t.Fatalf("err %v", err)
	}
	note, err := Find("yara-scan-cancel").Run(context.Background(), nil, taskstore.Task{})
	if err != nil || lastJSON(t, note)["state"] != "idle" {
		t.Fatalf("cancel with YARA off: %q %v", note, err)
	}
}

func TestYARAScanCancel(t *testing.T) {
	id := yara.NewID()
	withYARAScanner(t, &fakeYARAScanner{running: id})
	note, err := Find("yara-scan-cancel").Run(context.Background(), nil, taskstore.Task{})
	if err != nil {
		t.Fatal(err)
	}
	if got := lastJSON(t, note); got["scan_id"] != id || got["state"] != "cancelled" {
		t.Fatalf("result %v", got)
	}
	note, err = Find("yara-scan-cancel").Run(context.Background(), nil, taskstore.Task{})
	if err != nil || lastJSON(t, note)["state"] != "idle" {
		t.Fatalf("second cancel %q %v", note, err)
	}
}
