//go:build windows && (amd64 || arm64)

package filedlp

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"sentinelgo/internal/dlp/events"
)

// fakeTrace replaces the ETW trace: the test calls open as ETW would.
type fakeTrace struct {
	mu   sync.Mutex
	open func(fileOpen)
}

func (f *fakeTrace) install(t *testing.T, err error) {
	t.Helper()
	prev := startTrace
	startTrace = func(on func(fileOpen)) (*etwSession, error) {
		if err != nil {
			return nil, err
		}
		f.mu.Lock()
		f.open = on
		f.mu.Unlock()
		done := make(chan struct{})
		close(done)
		return &etwSession{done: done}, nil
	}
	t.Cleanup(func() { startTrace = prev })
}

func (f *fakeTrace) started() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.open != nil }

// opened reports an open of path (a drive-letter path) by pid, with the NT
// path ETW would give.
func (f *fakeTrace) opened(t *testing.T, pid uint32, path string) {
	t.Helper()
	for _, p := range ntDevices() {
		if strings.EqualFold(path[:2], p.dos) {
			f.mu.Lock()
			on := f.open
			f.mu.Unlock()
			on(fileOpen{pid: pid, path: p.nt + path[2:]})
			return
		}
	}
	t.Fatalf("no NT device for %s", path[:2])
}

// The temp folder is under the user profiles folder, where taint looks for
// sources; skip where it isn't.
func needProfileTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if p := profilesDir(); p == "" || !strings.HasPrefix(strings.ToLower(dir), p) {
		t.Skipf("temp folder %s isn't under the profiles folder", dir)
	}
	return dir
}

func TestWindowsTaint_EndToEnd(t *testing.T) {
	home := needProfileTemp(t)
	trace := &fakeTrace{}
	trace.install(t, nil)
	drive := fakeDrive(t, winVolume{})
	e, sink, _ := startEnforcer(t, winBundleAction(`, "audit_only": false, "copy_correlation": {"process_taint": true}`, "block"))
	eventually(t, "the trace", trace.started)
	if cc := e.CopyCorrelation(); cc[MethodProcessTaint] != "supported" {
		t.Errorf("capability %v", cc)
	}
	pid := windows.GetCurrentProcessId()

	secret := filepath.Join(home, "plan.txt")
	if err := os.WriteFile(secret, []byte("the TOPSECRET plan"), 0o600); err != nil {
		t.Fatal(err)
	}
	trace.opened(t, pid, secret)
	out := filepath.Join(drive, "out.bin")
	if err := os.WriteFile(out, []byte{1, 2, 3, 0, 0xff, 'b', 'i', 'n'}, 0o600); err != nil {
		t.Fatal(err)
	}
	trace.opened(t, pid, out)
	eventually(t, "the correlated event", func() bool { return len(sink.events()) == 1 })
	ev := sink.events()[0]
	if ev.Correlation == nil || ev.Correlation.Method != "taint" || ev.Scan.VerdictSource != "correlation" ||
		ev.Correlation.SourceName == nil || *ev.Correlation.SourceName != "plan.txt" || ev.Findings[0].Detector != "custom.keywords" {
		t.Fatalf("event %+v correlation %+v", ev, ev.Correlation)
	}
	if ev.Process == nil || !strings.HasSuffix(strings.ToLower(ev.Process.Path), ".exe") {
		t.Errorf("the writer isn't named: %+v", ev.Process)
	}
	if ev.Action != events.ActionMonitored {
		t.Errorf("action %q (on_close_violation is record)", ev.Action)
	}

	// A write no source is known for: no event.
	other := filepath.Join(drive, "other.bin")
	if err := os.WriteFile(other, []byte{1, 2, 3, 0, 0xff}, 0o600); err != nil {
		t.Fatal(err)
	}
	trace.opened(t, pid+100000, other) // a process that read nothing
	time.Sleep(time.Second)
	if n := len(sink.events()); n != 1 {
		t.Errorf("%d events: an untainted write was correlated", n)
	}
	if h := e.Health(); h.TaintProcesses != 1 {
		t.Errorf("health %+v", h)
	}
}

func TestWindowsTaint_TraceRefused(t *testing.T) {
	(&fakeTrace{}).install(t, windows.ERROR_ACCESS_DENIED)
	fakeDrive(t, winVolume{})
	e, _, _ := startEnforcer(t, winBundle(`, "copy_correlation": {"process_taint": true}`))
	eventually(t, "the failure to be reported", func() bool {
		return e.CopyCorrelation()[MethodProcessTaint] == "unsupported:not_permitted"
	})
	if c := e.Capabilities(); c["file.removable"] != "supported" {
		t.Errorf("scan after write must keep working: %v", c)
	}
}

func TestWinTaint_Paths(t *testing.T) {
	tk := &winTaint{store: newTaintStore(), writers: map[string]writerRef{}, profiles: `c:\users\`}
	devs := []ntPrefix{{nt: `\Device\HarddiskVolume3`, dos: "C:"}, {nt: `\Device\HarddiskVolume12`, dos: "E:"}}
	tk.devices.Store(&devs)
	roots := []string{`e:\`}
	tk.watched.Store(&roots)

	tk.onOpen(fileOpen{pid: 7, path: `\Device\HarddiskVolume3\Users\ann\plan.txt`})
	tk.onOpen(fileOpen{pid: 7, path: `\Device\HarddiskVolume3\Windows\notepad.exe`}) // not a user file
	tk.onOpen(fileOpen{pid: 7, path: `\Device\HarddiskVolume12\copy.txt`})
	tk.onOpen(fileOpen{pid: 7, path: `\Device\HarddiskVolume1\x.txt`})   // unknown device
	tk.onOpen(fileOpen{pid: 7, path: `\Device\HarddiskVolume31\x.txt`})  // a longer number isn't volume 3
	now := time.Now()
	if src := tk.store.sources(7, time.Time{}, now, time.Minute); len(src) != 1 || src[0].Path != `C:\Users\ann\plan.txt` {
		t.Errorf("sources %+v", src)
	}
	if pid, ok := tk.writer(`E:\COPY.TXT`, now, time.Minute); !ok || pid != 7 {
		t.Errorf("writer %d %v", pid, ok)
	}
	if _, ok := tk.writer(`E:\copy.txt`, now.Add(2*time.Minute), time.Minute); ok {
		t.Error("a writer past the window")
	}
}

// The real trace, as admin: an open of a file shows up with our PID's NT
// path. Run elevated: go test -run TestETW_RealTrace ./internal/dlp/filedlp/
func TestETW_RealTrace(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated prompt: ETW sessions need admin")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "etw-probe.txt")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	seen := make(chan string, 1024)
	// The callback skips the agent's own opens, so a child process opens it.
	s, err := startETW(func(o fileOpen) {
		if strings.HasSuffix(strings.ToLower(o.path), `\etw-probe.txt`) {
			select {
			case seen <- o.path:
			default:
			}
		}
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.stop()
	deadline := time.After(15 * time.Second)
	for {
		cmd := `type "` + path + `" > nul`
		_ = runCmd(cmd)
		select {
		case p := <-seen:
			if !strings.HasPrefix(p, `\Device\`) {
				t.Errorf("not an NT path: %s", p)
			}
			if ev, _ := s.stats(); ev == 0 {
				t.Error("no events counted")
			}
			return
		case <-deadline:
			t.Fatal("the open never showed up")
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func runCmd(cmd string) error {
	p, err := os.StartProcess(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), []string{"cmd", "/c", cmd},
		&os.ProcAttr{Files: []*os.File{nil, nil, nil}})
	if err != nil {
		return err
	}
	st, err := p.Wait()
	if err == nil && !st.Success() {
		err = errors.New(st.String())
	}
	return err
}
