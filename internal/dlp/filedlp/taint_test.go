package filedlp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/dlp/detect"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/filescan"
)

func TestTaintStore(t *testing.T) {
	s := newTaintStore()
	t0 := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	for i := 0; i < taintPerProcess+5; i++ {
		s.record(7, SourceRef{Path: fmt.Sprint(i), Ino: uint64(i), At: t0.Add(time.Duration(i) * time.Second)})
	}
	got := s.sources(7, time.Time{}, t0.Add(time.Minute), time.Hour)
	if len(got) != taintMaxSources || got[0].Path != fmt.Sprint(taintPerProcess+4) {
		t.Errorf("newest first, capped: %v", got)
	}
	// A file opened again moves to the front.
	s.record(7, SourceRef{Path: "10", Ino: 10, At: t0.Add(time.Hour)})
	if got := s.sources(7, time.Time{}, t0.Add(time.Hour), time.Hour); got[0].Path != "10" {
		t.Errorf("reopened: %v", got[0])
	}
	// Opens before the process started (a reused pid) and outside the
	// window don't count.
	if got := s.sources(7, t0.Add(time.Hour), t0.Add(time.Hour), time.Hour); len(got) != 1 {
		t.Errorf("since: %v", got)
	}
	if got := s.sources(7, time.Time{}, t0.Add(3*time.Hour), time.Minute); len(got) != 0 {
		t.Errorf("window: %v", got)
	}
	if s.sources(99, time.Time{}, t0, time.Hour) != nil {
		t.Error("unknown pid")
	}
	s.prune(t0.Add(3*time.Hour), time.Minute)
	if s.len() != 0 {
		t.Errorf("not pruned: %d", s.len())
	}
	// Bounded number of processes.
	for pid := 0; pid < taintMaxProcs+10; pid++ {
		s.record(pid, SourceRef{At: t0.Add(time.Duration(pid))})
	}
	if s.len() != taintMaxProcs {
		t.Errorf("%d processes", s.len())
	}
}

// byNameScanner answers per file, by the name it was opened under.
type byNameScanner struct{ res map[string]filescan.Result }

func (b byNameScanner) Scan(_ context.Context, f *os.File, _ int64, _ time.Duration) filescan.Result {
	return b.res[filepath.Base(f.Name())]
}

func taintBundle(action, extra string) string {
	return fmt.Sprintf(`{"schema_version": 1, "version": "v1", "enabled": true, "evidence_mode": "masked",
	  "modules": {"files": {"enabled": true, "channels": {"file.removable": true}, "audit_only": false, "on_unscannable": "monitor",
	    "copy_correlation": {"process_taint": true, "on_close_violation": "delete"%s}}},
	  "policies": [{"id": "p1", "name": "Cards", "channels": ["file.removable"], "action": %q,
	    "detectors": [{"id": "pii.credit_card", "rule_id": "r1", "min_count": 1}]}]}`, extra, action)
}

func TestDecider_ProcessTaint(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string) SourceRef {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		return SourceRef{Path: "/home/alice/" + name, At: time.Now()}
	}
	cards, notes, gone := mk("cards.csv"), mk("notes.txt"), SourceRef{Path: "/home/alice/gone.txt"}
	inodes := map[string]uint64{cards.Path: 1, notes.Path: 2}
	opener := func(src SourceRef) (*os.File, Identity, error) {
		if src.Path == gone.Path {
			return nil, Identity{}, os.ErrNotExist
		}
		f, err := os.Open(filepath.Join(dir, filepath.Base(src.Path)))
		return f, Identity{Dev: 1, Ino: inodes[src.Path], Size: 1}, err
	}
	sensitive := filescan.Result{Status: filescan.StatusScanned, SHA256: strings.Repeat("ab", 32), Findings: []detect.Finding{cardFinding()}}
	scanner := byNameScanner{res: map[string]filescan.Result{
		"cards.csv": sensitive,
		"notes.txt": {Status: filescan.StatusScanned},
	}}
	encrypted := filescan.Result{Status: filescan.Unscannable(filescan.ReasonPasswordProtected), DetectedType: "archive.zip", SHA256: strings.Repeat("cd", 32)}
	cleanText := filescan.Result{Status: filescan.StatusScanned, DetectedType: "text.utf8", SHA256: strings.Repeat("ef", 32)}

	run := func(bundle string, dest filescan.Result, sources []SourceRef) ([]events.Event, int) {
		sink := &recordingSink{}
		scanner.res["dest"] = dest
		d := NewDecider(scanner, sink)
		d.SetSourceOpener(opener)
		removed := 0
		d.SetRemediator(func(Request, string) error { removed++; return nil })
		d.Apply(compile(t, bundle))
		destPath := filepath.Join(t.TempDir(), "dest") // the scanner answers by this name
		if err := os.WriteFile(destPath, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		g, err := os.Open(destPath)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = g.Close() }()
		r := usbRequest()
		r.File, r.Sources = g, sources
		d.Handle(context.Background(), r)
		return sink.events(), removed
	}

	// An encrypted archive written after reading a sensitive file: judged by
	// that file; the block policy's after-write action applies.
	evs, removed := run(taintBundle("block", ""), encrypted, []SourceRef{notes, gone, cards})
	if len(evs) != 1 || evs[0].Correlation == nil || evs[0].Correlation.Method != "taint" || evs[0].Scan.VerdictSource != "correlation" ||
		*evs[0].Correlation.SourceName != "cards.csv" || evs[0].Correlation.SourceSHA256 != sensitive.SHA256 ||
		evs[0].File.SHA256 != encrypted.SHA256 || evs[0].Action != events.ActionDeleted || removed != 1 || len(evs[0].Findings) != 1 {
		t.Fatalf("correlated: %+v (removed %d)", evs, removed)
	}
	// A readable clean file is judged on its own: its writer's earlier reads
	// aren't held against it.
	if evs, _ := run(taintBundle("block", ""), cleanText, []SourceRef{cards}); len(evs) != 0 {
		t.Errorf("clean readable file correlated: %+v", evs)
	}
	// No sensitive source: the usual unscannable event, no correlation.
	evs, removed = run(taintBundle("block", ""), encrypted, []SourceRef{notes, gone})
	if len(evs) != 1 || evs[0].Correlation != nil || evs[0].Scan.VerdictSource != "scan" || removed != 0 {
		t.Errorf("no sensitive source: %+v", evs)
	}
	// Taint off: no correlation even with a sensitive source.
	off := strings.Replace(taintBundle("block", ""), `"process_taint": true`, `"process_taint": false`, 1)
	if evs, _ := run(off, encrypted, []SourceRef{cards}); len(evs) != 1 || evs[0].Correlation != nil {
		t.Errorf("taint off: %+v", evs)
	}
	// A monitor policy records the correlation and touches nothing.
	evs, removed = run(taintBundle("monitor", ""), encrypted, []SourceRef{cards})
	if len(evs) != 1 || evs[0].Correlation == nil || evs[0].Action != events.ActionMonitored || removed != 0 {
		t.Errorf("monitor: %+v %d", evs, removed)
	}
	if d := NewDecider(scanner, &recordingSink{}); d.Stats().Correlated != 0 {
		t.Error("stats")
	}
}
