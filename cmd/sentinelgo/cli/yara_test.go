package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/yara"
	"sentinelgo/internal/yara/scan"
)

// ruleTextMarker stands for rule text; the status never holds it, and the
// command must never print it.
const ruleTextMarker = "RULE-TEXT-MARKER-5d1e"

func fakeYARAConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{Path: filepath.Join(t.TempDir(), "config.json"), YARAEnabled: true}
	prev := loadDefaultConfig
	t.Cleanup(func() { loadDefaultConfig = prev })
	loadDefaultConfig = func() (*config.Config, error) { return cfg, nil }
	return cfg
}

func TestRunYARA_Status(t *testing.T) {
	cfg := fakeYARAConfig(t)
	finished := time.Date(2026, 11, 11, 9, 30, 0, 0, time.UTC)
	ls := scan.LocalStatus{
		UpdatedAt: finished, LocalEnabled: true,
		Status: yara.Status{State: yara.StateOK, AppliedVersion: "abc123", AgentVersion: "1.2.3", EngineVersion: "0.9.0",
			Rulesets: []yara.RulesetStatus{{ID: "rs-1", Revision: 3, CompiledRules: 5,
				SkippedRules: []yara.SkippedRule{{Rule: "uses_pe", Line: 4, Reason: "unsupported_module:pe"}}}},
			LastScan: &yara.ScanSummary{ScanID: "scan-1", Trigger: yara.TriggerScheduled, Preset: yara.PresetQuick,
				State: yara.ScanCompleted, FinishedAt: finished, FilesScanned: 120, Matches: 1}},
		Workers:      &scan.Workers{Live: 1, Sandbox: "appcontainer"},
		Schedules:    []scan.ScheduleStatus{{ID: "sched-1", Preset: yara.PresetQuick, EveryHours: 24, NextRun: finished.Add(24 * time.Hour)}},
		QueuedEvents: 2,
		OnWrite: &scan.OnWriteStatus{Watching: 5, Pending: 1, Dropped: 3,
			Window: &scan.OnWriteWindow{ScanID: "win-1", Started: finished, Scanned: 40, Matches: 1}},
	}
	if err := scan.WriteStatus(filepath.Join(filepath.Dir(cfg.Path), scan.StatusFileName), ls); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := RunYARA([]string{"status"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	for _, want := range []string{"State:                       ok", "Applied bundle version:      abc123",
		"Rulesets:                    1 (5 rules compiled, 1 skipped)", "skipped uses_pe (line 4): unsupported_module:pe",
		"scan-1 completed (scheduled quick)", "120 scanned", "schedule sched-1: quick every 24h", "2 events awaiting upload",
		"On-write scanning:           on, 5 folders watched, 1 files waiting", "3 files dropped", "window win-1"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), ruleTextMarker) {
		t.Fatal("rule text printed")
	}

	out.Reset()
	if code := RunYARA([]string{"status", "-json"}, &out, &errOut); code != 0 {
		t.Fatalf("json exit %d", code)
	}
	var back scan.LocalStatus
	if err := json.Unmarshal(out.Bytes(), &back); err != nil || back.Status.AppliedVersion != "abc123" {
		t.Errorf("json %s (%v)", out.String(), err)
	}
}

func TestRunYARA_NoStatusAndUsage(t *testing.T) {
	fakeYARAConfig(t)
	var out, errOut bytes.Buffer
	if code := RunYARA([]string{"status"}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "No threat hunting status yet") {
		t.Errorf("exit %d, stderr %q", code, errOut.String())
	}
	if code := RunYARA(nil, &out, &errOut); code != 2 {
		t.Errorf("no args: exit %d", code)
	}
}
