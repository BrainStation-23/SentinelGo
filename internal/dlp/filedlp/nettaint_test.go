package filedlp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/dlp/detect"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/filescan"
	"sentinelgo/internal/dlp/policy"
)

func netTaintBundle(auditOnly bool, uploadChannel bool) string {
	return fmt.Sprintf(`{"schema_version": 1, "version": "v1", "enabled": true, "evidence_mode": "masked",
	  "modules": {"files": {"enabled": true, "channels": {"file.upload": %v}, "audit_only": %v,
	    "egress_apps": {"windows": [{"name": "chrome.exe"}]},
	    "network_control": {"enabled": true, "taint_block": {"enabled": true, "minutes": 5}}}},
	  "policies": [{"id": "p1", "name": "Cards", "channels": ["file.upload"], "action": "block",
	    "detectors": [{"id": "pii.credit_card", "rule_id": "r1", "min_count": 1}]}]}`, uploadChannel, auditOnly)
}

var chromeProc = Process{PID: 7, Name: "chrome.exe", Exe: `C:\Program Files\Google\Chrome\Application\chrome.exe`, UID: "1", User: "ana"}

// sensitiveScanner finds a card number in files whose name contains "card".
type sensitiveScanner struct {
	mu    sync.Mutex
	scans int
}

func (s *sensitiveScanner) Scan(_ context.Context, f *os.File, size int64, _ time.Duration) filescan.Result {
	s.mu.Lock()
	s.scans++
	s.mu.Unlock()
	if strings.Contains(filepath.Base(f.Name()), "card") {
		return filescan.Result{Status: filescan.StatusScanned, Size: size, SHA256: strings.Repeat("ab", 32), Findings: []detect.Finding{cardFinding()}}
	}
	return filescan.Result{Status: filescan.StatusScanned, Size: size, SHA256: strings.Repeat("cd", 32)}
}

func (s *sensitiveScanner) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scans
}

func tempFile(t *testing.T, dir, name string) (*os.File, Identity) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("4111 1111 1111 1111"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f, Identity{Dev: 1, Ino: uint64(len(name)), Size: 19, ModTime: 1, ChangeTime: 1}
}

func TestDecideNetworkTaint(t *testing.T) {
	fastNotices(t)
	at := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	run := func(bundle, name string) (*Decider, *recordingSink, *fakeUserNotifier, time.Time, bool) {
		sink := &recordingSink{}
		fn := &fakeUserNotifier{readiness: map[string]string{"1": "supported"}}
		d := NewDecider(&sensitiveScanner{}, sink)
		d.SetUserNotifier(fn)
		d.Apply(compile(t, bundle))
		f, ident := tempFile(t, t.TempDir(), name)
		until, block := d.DecideNetworkTaint(context.Background(), Request{File: f, Path: f.Name(), Proc: chromeProc, Ident: ident, At: at})
		return d, sink, fn, until, block
	}

	d, sink, fn, until, block := run(netTaintBundle(false, true), "cards.xlsx")
	if !block || !until.Equal(at.Add(5*time.Minute)) {
		t.Fatalf("block %v until %v", block, until)
	}
	evs := sink.events()
	if len(evs) != 1 {
		t.Fatalf("events %+v", evs)
	}
	ev := evs[0]
	if ev.Action != events.ActionBlocked || ev.Channel != policy.ChannelFileUpload || ev.Destination.Type != TypeNetwork ||
		ev.Correlation == nil || ev.Correlation.Method != "taint" || *ev.Correlation.SourceName != "cards.xlsx" ||
		ev.NetworkBlock == nil || ev.NetworkBlock.Minutes != 5 || !ev.NetworkBlock.Until.Equal(until) ||
		ev.Process.Name != "chrome.exe" || ev.UserNotified == nil || !*ev.UserNotified {
		t.Errorf("event %+v dest %+v corr %+v block %+v", ev, ev.Destination, ev.Correlation, ev.NetworkBlock)
	}
	d.notices.wait()
	shown := fn.all()
	if len(shown) != 1 || !strings.Contains(shown[0], "SentinelOps paused chrome.exe's network access") ||
		!strings.Contains(shown[0], `"cards.xlsx"`) || !strings.Contains(shown[0], "pii.credit_card") ||
		!strings.Contains(shown[0], "5 minutes") || strings.Contains(shown[0], "4111") {
		t.Errorf("notice %q", shown)
	}

	// Audit-only: recorded as would_have, not blocked, nobody told.
	_, sink, _, _, block = run(netTaintBundle(true, true), "cards.xlsx")
	if evs := sink.events(); block || len(evs) != 1 || evs[0].Action != events.ActionMonitored || evs[0].WouldHave != events.NetworkBlocked {
		t.Errorf("audit-only: block %v events %+v", block, evs)
	}
	// A clean file, or the upload channel off: nothing.
	if _, sink, _, _, block := run(netTaintBundle(false, true), "notes.txt"); block || len(sink.events()) != 0 {
		t.Errorf("clean file: block %v events %d", block, len(sink.events()))
	}
	if _, sink, _, _, block := run(netTaintBundle(false, false), "cards.xlsx"); block || len(sink.events()) != 0 {
		t.Errorf("upload channel off: block %v events %d", block, len(sink.events()))
	}
}

type fakeTainter struct {
	mu    sync.Mutex
	exes  []string
	until []time.Time
}

func (f *fakeTainter) TaintBlock(exe string, until time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.exes = append(f.exes, exe)
	f.until = append(f.until, until)
}

func (f *fakeTainter) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.exes)
}

func TestEgressTaints(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"cards.xlsx", "cards2.xlsx", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	scanner := &sensitiveScanner{}
	d := NewDecider(scanner, &recordingSink{})
	c := compile(t, netTaintBundle(false, true))
	d.Apply(c)
	tainter := &fakeTainter{}
	current := c
	g := newEgressTaints(d, tainter, "windows", func() *policy.Compiled { return current })
	procs := map[uint32]Process{7: chromeProc, 8: {PID: 8, Name: "notepad.exe", Exe: `C:\Windows\notepad.exe`}}
	g.procInfo = func(pid uint32) Process { return procs[pid] }
	g.open = func(src SourceRef) (*os.File, Identity, error) {
		f, err := os.Open(src.Path)
		return f, Identity{Dev: 1, Ino: uint64(len(src.Path)), Size: 1, ModTime: 1, ChangeTime: 1}, err
	}
	at := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	open := func(pid uint32, name string, after time.Duration) {
		g.handle(context.Background(), egressOpen{pid: pid, path: filepath.Join(dir, name), at: at.Add(after)})
	}

	open(8, "cards.xlsx", 0) // not an egress app: not even scanned
	if scanner.count() != 0 || tainter.calls() != 0 {
		t.Fatalf("non-egress app: scans %d taints %d", scanner.count(), tainter.calls())
	}
	open(7, "notes.txt", 0) // clean
	open(7, "cards.xlsx", time.Second)
	if tainter.calls() != 1 || tainter.exes[0] != chromeProc.Exe || !tainter.until[0].Equal(at.Add(time.Second+5*time.Minute)) {
		t.Fatalf("taint %+v", tainter)
	}
	// While cut off, the app's opens aren't judged.
	before := scanner.count()
	open(7, "cards2.xlsx", time.Minute)
	if scanner.count() != before || tainter.calls() != 1 {
		t.Errorf("judged while blocked: scans %d taints %d", scanner.count(), tainter.calls())
	}
	// After the block, a file judged lately isn't judged again; another is.
	open(7, "notes.txt", 6*time.Minute)
	if scanner.count() != before {
		t.Errorf("rechecked within the window")
	}
	open(7, "cards2.xlsx", 7*time.Minute)
	if tainter.calls() != 2 {
		t.Errorf("second taint: %d", tainter.calls())
	}
	// Taint blocks off: nothing.
	current = compile(t, strings.Replace(netTaintBundle(false, true), `"taint_block": {"enabled": true`, `"taint_block": {"enabled": false`, 1))
	open(7, "cards.xlsx", 30*time.Minute)
	if tainter.calls() != 2 {
		t.Errorf("taint with taint blocks off")
	}
}

func TestEgressTaints_QueueAndPaths(t *testing.T) {
	defer func(n int) { egressQueueSize = n }(egressQueueSize)
	egressQueueSize = 2
	g := newEgressTaints(nil, nil, "windows", func() *policy.Compiled { return nil })
	for i := 0; i < 5; i++ {
		g.offer(egressOpen{pid: 1, path: "x"})
	}
	if g.dropped.Load() != 3 {
		t.Errorf("dropped %d", g.dropped.Load())
	}
	if userFile(`c:\users\ana\appdata\local\google\chrome\user data\default\cache\f_0001`) ||
		!userFile(`c:\users\ana\documents\q3.xlsx`) {
		t.Error("userFile")
	}
}

// run handles queued opens until its context ends.
func TestEgressTaints_Run(t *testing.T) {
	handled := make(chan struct{}, 1)
	g := newEgressTaints(nil, nil, "windows", func() *policy.Compiled {
		select {
		case handled <- struct{}{}:
		default:
		}
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.run(ctx); close(done) }()
	g.offer(egressOpen{pid: 1, path: "x"})
	select {
	case <-handled:
	case <-time.After(5 * time.Second):
		t.Fatal("open not handled")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run didn't stop")
	}
}
