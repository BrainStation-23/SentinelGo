package filedlp

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"sentinelgo/internal/dlp/detect"
	"sentinelgo/internal/dlp/filescan"
)

func TestIsTempName(t *testing.T) {
	for name, want := range map[string]bool{
		"lu12345abcd.tmp":            true,
		"~WRL0003.tmp":               true,
		"REPORT.TMP":                 true,
		"~$plan.docx":                true,
		".goutputstream-ABC123":      true,
		"1A2b3C4d":                   true,
		".~lock.plan.docx#":          false,
		"plan.docx":                  false,
		"notes.txt":                  false,
		"1A2b3C4g":                   false,
		"1A2b3C4":                    false,
		"tmp":                        false,
		"archive.tmp.zip":            false,
		".goutputstream":             false,
		"~WRL0003.tmp.docx-not-temp": false,
	} {
		if got := isTempName(name); got != want {
			t.Errorf("%q: %v", name, got)
		}
	}
}

// settle: a renamed file is queued under its new name, a deleted one is
// dropped, one linked elsewhere is still decided, and one that keeps its
// name waits until its hold ends.
func TestSettle(t *testing.T) {
	stick := t.TempDir()
	e := New(Options{}).(*linuxEnforcer)
	dests := []Destination{{Mount: stick, VolumeLabel: "STICK"}}
	e.dests.Store(&dests)
	queue := make(chan Request, 4)
	open := func(name string) *Request {
		t.Helper()
		p := filepath.Join(stick, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(p) // #nosec G304 -- a test file
		if err != nil {
			t.Fatal(err)
		}
		return &Request{File: f, Path: p}
	}

	r := open("lu1.tmp")
	if e.settle(r, false, queue) || len(queue) != 0 {
		t.Fatal("decided before its rename")
	}
	if err := os.Rename(r.Path, filepath.Join(stick, "plan.docx")); err != nil {
		t.Fatal(err)
	}
	if !e.settle(r, false, queue) {
		t.Fatal("rename not seen")
	}
	if got := <-queue; got.Path != filepath.Join(stick, "plan.docx") || got.Dest.VolumeLabel != "STICK" {
		t.Fatalf("queued %+v", got)
	}
	_ = r.File.Close()

	r = open("lu2.tmp")
	if err := os.Remove(r.Path); err != nil {
		t.Fatal(err)
	}
	if !e.settle(r, false, queue) || len(queue) != 0 {
		t.Fatal("a deleted temp file was decided")
	}

	r = open("lu3.tmp")
	if err := os.Link(r.Path, filepath.Join(stick, "kept")); err != nil {
		t.Skip(err)
	}
	if err := os.Remove(r.Path); err != nil {
		t.Fatal(err)
	}
	if !e.settle(r, false, queue) || len(queue) != 1 {
		t.Fatal("a file still linked under another name was dropped")
	}
	_ = (<-queue).File.Close()

	r = open("lu4.tmp")
	if !e.settle(r, true, queue) || (<-queue).Path != r.Path {
		t.Fatal("an expired hold wasn't decided under its name")
	}
	_ = r.File.Close()

	// A full queue drops the file and counts it.
	full := make(chan Request)
	r = open("lu5.tmp")
	if !e.settle(r, true, full) || e.dropped.Load() != 1 {
		t.Fatal("full queue")
	}
	// Too many held: decided at once.
	if hold(Request{}, make(chan Request)) {
		t.Fatal("held past the limit")
	}
}

// Through the loops (fake fanotify): a save through a temp file is reported
// under the document's name; a temp file deleted unread is not reported; one
// that is never renamed is reported under its own name when its hold ends.
func TestEnforcer_TempFileSaves(t *testing.T) {
	prevHold, prevPoll := renameHold, renamePoll
	renameHold, renamePoll = 500*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { renameHold, renamePoll = prevHold, prevPoll })
	stick := t.TempDir()
	ff := installFakeFanotify(t, "")
	fakeMounts(t, stick)
	sink := &recordingSink{}
	e := New(Options{Sink: sink}).(*linuxEnforcer)
	e.decider = NewDecider(&fakeScanner{res: filescan.Result{Status: filescan.StatusScanned, DetectedType: "text.utf8",
		Findings: []detect.Finding{{DetectorID: "custom.keywords", RuleID: "kw", Count: 1, Offsets: [][2]int{{0, 9}}}}}}, sink)
	e.Apply(context.Background(), compile(t, enforcerBundle))
	t.Cleanup(e.Stop)
	eventually(t, "the stick to be marked", func() bool { return ff.isMarked(stick) && e.Health().Mounts == 1 })

	write := func(name string) string {
		t.Helper()
		p := filepath.Join(stick, name)
		if err := os.WriteFile(p, []byte("TOPSECRET"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	tmp := write("lu98765.tmp")
	ff.event(t, unix.FAN_CLOSE_WRITE, openFD(t, tmp), 1)
	eventually(t, "the event to be read", ff.drained)
	time.Sleep(50 * time.Millisecond)
	if err := os.Rename(tmp, filepath.Join(stick, "plan.docx")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the save's event", func() bool { return len(sink.events()) == 1 })
	if ev := sink.events()[0]; *ev.File.Name != "plan.docx" || ev.File.Ext != "docx" {
		t.Errorf("event file %+v", ev.File)
	}

	gone := write("~WRL0001.tmp")
	ff.event(t, unix.FAN_CLOSE_WRITE, openFD(t, gone), 1)
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	stays := write("stays.tmp")
	ff.event(t, unix.FAN_CLOSE_WRITE, openFD(t, stays), 1)
	eventually(t, "the unrenamed temp file's event", func() bool { return len(sink.events()) == 2 })
	if ev := sink.events()[1]; *ev.File.Name != "stays.tmp" {
		t.Errorf("event file %+v", ev.File)
	}
	time.Sleep(2 * renameHold)
	if n := len(sink.events()); n != 2 {
		t.Errorf("%d events: the deleted temp file was reported", n)
	}

	// Stopping with files held closes them.
	held := write("held.tmp")
	ff.event(t, unix.FAN_CLOSE_WRITE, openFD(t, held), 1)
	eventually(t, "the event to be read", ff.drained)
	e.Stop()
}

// End to end on a real kernel: LibreOffice's and Office's ways of saving
// onto a document on the stick are reported under the document's name.
func TestEnforcer_TempFileSavesEndToEnd(t *testing.T) {
	stick := fakeStick(t, "serve")
	sink := &recordingSink{}
	e := New(Options{Sink: sink, Exe: testExe(t), ConfigDir: t.TempDir()})
	e.Apply(context.Background(), compile(t, enforcerBundle))
	t.Cleanup(e.Stop)
	if h := e.Health(); h == nil || h.State != stateRunning {
		t.Skipf("fanotify not available here: %+v", h)
	}
	eventually(t, "the stick to be watched", func() bool { return e.Health().Mounts == 1 })

	sh := func(script string) {
		t.Helper()
		cmd := exec.Command("/bin/sh", "-c", script)
		cmd.Dir = stick
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
	}
	// LibreOffice: a new temp file renamed onto the document.
	sh(`printf 'TOPSECRET plan' > lu4242abc.tmp && mv lu4242abc.tmp plan.odt`)
	eventually(t, "LibreOffice's save", func() bool { return hasEventFor(sink, "plan.odt") })
	// Office: the old document moved aside, the new one renamed onto its
	// name, the old one deleted.
	sh(`printf 'TOPSECRET draft' > ~WRL0001.tmp && mv budget.xlsx ~WRL0002.tmp 2>/dev/null; mv ~WRL0001.tmp budget.xlsx && rm -f ~WRL0002.tmp`)
	eventually(t, "Office's save", func() bool { return hasEventFor(sink, "budget.xlsx") })
	for _, ev := range sink.events() {
		if n := *ev.File.Name; isTempName(n) {
			t.Errorf("an event under the temp name %q", n)
		}
	}
}

func hasEventFor(sink *recordingSink, name string) bool {
	for _, ev := range sink.events() {
		if ev.File != nil && ev.File.Name != nil && *ev.File.Name == name {
			return true
		}
	}
	return false
}
