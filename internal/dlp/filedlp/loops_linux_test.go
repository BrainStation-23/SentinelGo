package filedlp

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	"sentinelgo/internal/dlp/detect"
	"sentinelgo/internal/dlp/filescan"
	"sentinelgo/internal/dlp/policy"
)

// fakeFanotify replaces the fanotify calls: the "group" is a pipe the test
// writes kernel-format event records into, and marks are recorded.
type fakeFanotify struct {
	mu      sync.Mutex
	w       *os.File
	marked  map[string]bool
	adds    int
	removes int
	failFor string // a mount point whose mark fails
}

func installFakeFanotify(t *testing.T, failFor string) *fakeFanotify {
	t.Helper()
	ff := &fakeFanotify{marked: map[string]bool{}, failFor: failFor}
	prevInit, prevMark := fanotifyInit, markMount
	fanotifyInit = func() (int, error) {
		var p [2]int
		if err := unix.Pipe2(p[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
			return -1, err
		}
		ff.w = os.NewFile(uintptr(p[1]), "fake-fanotify-w")
		return p[0], nil
	}
	markMount = func(_ int, add bool, mp string) error {
		ff.mu.Lock()
		defer ff.mu.Unlock()
		if add && mp == ff.failFor {
			return unix.EACCES
		}
		if add {
			ff.adds++
			ff.marked[mp] = true
		} else {
			ff.removes++
			delete(ff.marked, mp)
		}
		return nil
	}
	t.Cleanup(func() {
		fanotifyInit, markMount = prevInit, prevMark
		if ff.w != nil {
			_ = ff.w.Close()
		}
	})
	return ff
}

func (ff *fakeFanotify) isMarked(mp string) bool {
	ff.mu.Lock()
	defer ff.mu.Unlock()
	return ff.marked[mp]
}

// drained reports whether the enforcer has read everything written so far.
func (ff *fakeFanotify) drained() bool {
	n, err := unix.IoctlGetInt(int(ff.w.Fd()), unix.TIOCINQ) // #nosec G115 -- a descriptor
	return err == nil && n == 0
}

// event writes one fanotify_event_metadata record.
func (ff *fakeFanotify) event(t *testing.T, mask uint64, fd, pid int) {
	t.Helper()
	b := make([]byte, metaLen)
	binary.NativeEndian.PutUint32(b[0:], metaLen)
	b[4] = unix.FANOTIFY_METADATA_VERSION
	binary.NativeEndian.PutUint16(b[6:], metaLen)
	binary.NativeEndian.PutUint64(b[8:], mask)
	binary.NativeEndian.PutUint32(b[16:], uint32(int32(fd)))  // #nosec G115 -- test data
	binary.NativeEndian.PutUint32(b[20:], uint32(int32(pid))) // #nosec G115 -- test data
	if _, err := ff.w.Write(b); err != nil {
		t.Fatal(err)
	}
}

// openFD opens path and returns a raw descriptor the enforcer will own (and
// close), as the kernel's event descriptors are.
func openFD(t *testing.T, path string) int {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

// fakeMounts writes a mountinfo with the given mount points and classifies
// them as removable media (a "bad" one as a network share).
func fakeMounts(t *testing.T, mounts ...string) {
	t.Helper()
	var b strings.Builder
	for i, mp := range mounts {
		fmt.Fprintf(&b, "%d 1 8:%d / %s rw shared:1 - vfat /dev/sdx%d rw\n", 100+i, i+1, mp, i+1)
	}
	p := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	prevPath, prevClassify := mountinfoPath, classifyMount
	mountinfoPath = p
	classifyMount = func(m mountInfo, _ map[string]string) (Destination, bool) {
		return Destination{Channel: policy.ChannelFileRemovable, Type: TypeRemovable, Mount: m.MountPoint, VolumeLabel: "STICK"}, true
	}
	t.Cleanup(func() { mountinfoPath, classifyMount = prevPath, prevClassify })
}

// The loops end to end without root: marks, events from the "group",
// decisions, the off switch and stopping.
func TestEnforcer_LoopsWithoutRoot(t *testing.T) {
	stick, other, broken := t.TempDir(), t.TempDir(), t.TempDir()
	ff := installFakeFanotify(t, broken)
	fakeMounts(t, stick, broken)
	cfgDir := t.TempDir()
	sink := &recordingSink{}
	e := New(Options{Sink: sink, ConfigDir: cfgDir}).(*linuxEnforcer)
	if e.Health() != nil {
		t.Error("health before the first start")
	}
	scanner := &fakeScanner{res: filescan.Result{Status: filescan.StatusScanned, DetectedType: "text.utf8",
		Findings: []detect.Finding{{DetectorID: "custom.keywords", RuleID: "kw", Count: 1, Offsets: [][2]int{{0, 9}}}}}}
	e.decider = NewDecider(scanner, sink)

	e.Apply(context.Background(), compile(t, enforcerBundle))
	t.Cleanup(e.Stop)
	eventually(t, "the stick to be marked", func() bool { return ff.isMarked(stick) && e.Health().Mounts == 1 })
	if ff.isMarked(broken) {
		t.Error("a mount whose mark failed counts as marked")
	}
	if got := e.Capabilities()[policy.ChannelFileRemovable]; got != "supported" {
		t.Errorf("capability %q", got)
	}

	// A file written on the stick by another process: one event.
	report := filepath.Join(stick, "report.txt")
	if err := os.WriteFile(report, []byte("TOPSECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	ff.event(t, unix.FAN_CLOSE_WRITE, openFD(t, report), 1)
	eventually(t, "the event", func() bool { return len(sink.events()) == 1 })
	ev := sink.events()[0]
	if *ev.File.Name != "report.txt" || ev.Destination.VolumeLabel != "STICK" || ev.Scan.VerdictSource != "scan" || ev.User == "" {
		t.Errorf("event %+v %+v", ev, ev.File)
	}

	// Ignored: a file elsewhere, a directory, our own write, and events
	// without a file (overflow, unreadable).
	outside := filepath.Join(other, "x.txt")
	if err := os.WriteFile(outside, []byte("TOPSECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	ff.event(t, unix.FAN_CLOSE_WRITE, openFD(t, outside), 1)
	ff.event(t, unix.FAN_CLOSE_WRITE, openFD(t, stick), 1)
	ff.event(t, unix.FAN_CLOSE_WRITE, openFD(t, report), os.Getpid())
	ff.event(t, unix.FAN_Q_OVERFLOW, -1, 0)
	ff.event(t, unix.FAN_CLOSE_WRITE, -1, 1)
	eventually(t, "the counters", func() bool { h := e.Health(); return h.Overflows == 1 && h.Unreadable == 1 })
	if n := len(sink.events()); n != 1 {
		t.Errorf("%d events after ignored ones", n)
	}

	// The emergency switch unmarks; removing it marks again.
	off := filepath.Join(cfgDir, OffSwitchFile)
	if err := os.WriteFile(off, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	e.Apply(context.Background(), compile(t, enforcerBundle)) // kicks a reconcile
	eventually(t, "the switch to unmark", func() bool { return !ff.isMarked(stick) && e.Health().State == stateLocalOff })
	if got := e.Capabilities()[policy.ChannelFileRemovable]; got != "unsupported:disabled_locally" {
		t.Errorf("capability while off: %q", got)
	}
	ff.event(t, unix.FAN_CLOSE_WRITE, openFD(t, report), 1)
	eventually(t, "the event to be read while off", ff.drained)
	if err := os.Remove(off); err != nil {
		t.Fatal(err)
	}
	e.Apply(context.Background(), compile(t, enforcerBundle))
	eventually(t, "marking again", func() bool { return ff.isMarked(stick) && e.Health().State == stateRunning })
	if n := len(sink.events()); n != 1 {
		t.Errorf("%d events, want 1: a write while switched off was recorded", n)
	}

	// A policy without the channel stops everything.
	e.Apply(context.Background(), compile(t, strings.Replace(enforcerBundle, `"file.removable": true`, `"file.removable": false`, 1)))
	if h := e.Health(); h.State != stateStopped || h.Mounts != 0 {
		t.Errorf("after the channel was turned off: %+v", h)
	}
	if caps := e.Capabilities(); len(caps) != 0 {
		t.Errorf("capabilities for channels that are off: %v", caps)
	}
	e.Stop()
	e.Stop() // idempotent
}

// Without permission for fanotify the channel says why.
func TestEnforcer_FanotifyUnavailable(t *testing.T) {
	prev := fanotifyInit
	t.Cleanup(func() { fanotifyInit = prev })
	for err, want := range map[error]string{
		unix.EPERM:  "unsupported:not_permitted",
		unix.ENOSYS: "unsupported:fanotify_unavailable",
		unix.EINVAL: "unsupported:fanotify_unavailable",
		unix.EMFILE: "unsupported:fanotify_error",
	} {
		fanotifyInit = func() (int, error) { return -1, err }
		e := New(Options{Sink: &recordingSink{}})
		e.Apply(context.Background(), compile(t, enforcerBundle))
		if got := e.Capabilities()[policy.ChannelFileRemovable]; got != want {
			t.Errorf("%v: capability %q, want %q", err, got, want)
		}
		if h := e.Health(); h == nil || !strings.HasPrefix(h.State, "unavailable:") {
			t.Errorf("%v: health %+v", err, h)
		}
		e.Stop()
	}
}

// A scan through the enforcer's pool when none is running fails cleanly.
func TestPoolScanner_NoPool(t *testing.T) {
	e := New(Options{}).(*linuxEnforcer)
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if res := (poolScanner{e}).Scan(context.Background(), f, 1, 0); !filescan.IsUnscannable(res.Status) {
		t.Errorf("status %q", res.Status)
	}
	if !e.Wants(policy.FilesModule{Enabled: true, Channels: map[string]bool{policy.ChannelFileNetworkShare: true}}) {
		t.Error("Wants network shares")
	}
	if e.Wants(policy.FilesModule{Enabled: true, Channels: map[string]bool{policy.ChannelFileUpload: true}}) {
		t.Error("Wants uploads")
	}
}

// The real fanotify calls behind the seams. As a normal user the kernel
// refuses them; as root they work and are undone.
func TestRealFanotifyCalls(t *testing.T) {
	fan, err := fanotifyInit()
	if err != nil {
		if os.Geteuid() == 0 {
			t.Skipf("fanotify unavailable here: %v", err)
		}
		if got := fanotifyFailure(err); !strings.HasPrefix(got, "unavailable:") {
			t.Errorf("failure %q", got)
		}
		if err := markMount(-1, true, t.TempDir()); err == nil {
			t.Error("marking with a bad descriptor succeeded")
		}
		if err := markMount(-1, false, t.TempDir()); err == nil {
			t.Error("unmarking with a bad descriptor succeeded")
		}
		return
	}
	defer func() { _ = unix.Close(fan) }()
	dir := t.TempDir()
	if err := markMount(fan, true, dir); err != nil {
		t.Fatalf("mark: %v", err)
	}
	if err := markMount(fan, false, dir); err != nil {
		t.Errorf("unmark: %v", err)
	}
}
