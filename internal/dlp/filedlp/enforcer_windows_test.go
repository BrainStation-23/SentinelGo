package filedlp

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"

	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
	"sentinelgo/internal/dlp/scanworker"
)

// The test binary doubles as the scan worker.
const workerTestEnv = "SENTINELGO_SCANWORKER_TEST"

// probeOpenEnv makes the test binary open one file and exit (a process
// other than the test, for the ETW trace).
const probeOpenEnv = "SENTINELGO_ETW_PROBE_OPEN"

func TestMain(m *testing.M) {
	if p := os.Getenv(probeOpenEnv); p != "" {
		if _, err := os.ReadFile(p); err != nil { // #nosec G304 -- the test's own temp file
			os.Exit(1)
		}
		os.Exit(0)
	}
	if os.Getenv(workerTestEnv) == "serve" {
		if err := scanworker.Serve(); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func winBundle(files string) string { return winBundleAction(files, "monitor") }

func winBundleAction(files, action string) string {
	return `{"schema_version": 1, "version": "v1", "enabled": true,
  "modules": {"files": {"enabled": true, "channels": {"file.removable": true}` + files + `}},
  "policies": [{"id": "p1", "name": "Secrets", "severity": "high", "channels": ["file.removable"], "action": "` + action + `",
    "detectors": [{"id": "custom.keywords", "rule_id": "kw", "min_count": 1, "keywords": ["TOPSECRET"]}]}]}`
}

// fakeDrive makes a temp folder play a removable drive.
func fakeDrive(t *testing.T, vol winVolume) string {
	t.Helper()
	dir := t.TempDir() + `\`
	vol.Destination = Destination{Channel: policy.ChannelFileRemovable, Type: TypeRemovable, Mount: dir, VolumeLabel: "TEST", Source: `\\?\Volume{test}\`, USB: vol.USB}
	listVolumes = func() []winVolume { return []winVolume{vol} }
	workerEnv = []string{workerTestEnv + "=serve"}
	oldQuiet, oldTick, oldPoll := quietFor, pendingTick, volumePoll
	quietFor, pendingTick, volumePoll = 200*time.Millisecond, 50*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() {
		listVolumes, workerEnv = removableVolumes, nil
		quietFor, pendingTick, volumePoll = oldQuiet, oldTick, oldPoll
	})
	return dir
}

func startEnforcer(t *testing.T, bundle string) (Enforcer, *recordingSink, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sink := &recordingSink{}
	cfgDir := t.TempDir()
	e := New(Options{Sink: sink, Exe: exe, ConfigDir: cfgDir})
	e.Apply(context.Background(), compile(t, bundle))
	t.Cleanup(e.Stop)
	return e, sink, cfgDir
}

func TestWindowsEnforcer_ScansAfterWrite(t *testing.T) {
	drive := fakeDrive(t, winVolume{})
	e, sink, cfgDir := startEnforcer(t, winBundle(""))
	eventually(t, "the drive to be watched", func() bool { h := e.Health(); return h != nil && h.Mounts == 1 })
	if caps := e.Capabilities(); caps[policy.ChannelFileRemovable] != "supported" {
		t.Errorf("caps %v", caps)
	}
	cc := e.CopyCorrelation()
	if cc[MethodScanOnClose] != "supported" || cc[MethodUntrustedDevices] != "supported" ||
		cc[MethodOSCopyEvents] != "unsupported:not_on_windows" || cc[MethodProcessTaint] != "supported" {
		t.Errorf("copy correlation %v", cc)
	}
	if h := e.Health(); h.Blocking != nil {
		t.Errorf("Windows never holds a file: %+v", h.Blocking)
	}

	if err := os.WriteFile(filepath.Join(drive, "clean.txt"), []byte("nothing to see"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A writer that keeps the file open: not scanned until it closes.
	f, err := os.Create(filepath.Join(drive, "report.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("quarterly TOPSECRET numbers"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(800 * time.Millisecond)
	if n := len(sink.events()); n != 0 {
		t.Fatalf("%d events while the writer still has the file open", n)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the event", func() bool { return len(sink.events()) == 1 })
	ev := sink.events()[0]
	if ev.Channel != policy.ChannelFileRemovable || ev.File == nil || ev.File.Name == nil || *ev.File.Name != "report.txt" ||
		ev.Destination.VolumeLabel != "TEST" || ev.Findings[0].Detector != "custom.keywords" || ev.Action != events.ActionMonitored {
		t.Errorf("event %+v file %+v", ev, ev.File)
	}
	// The clean file's scan isn't ordered before the other file's event
	// (each file waits out its own quiet period): wait for it.
	eventually(t, "both files scanned", func() bool { return e.Health().Stats.Scans >= 2 })
	if h := e.Health(); !strings.Contains(h.Workers.Sandbox, "job") {
		t.Errorf("health %+v", h)
	}
	if _, err := os.Stat(filepath.Join(drive, "report.txt")); err != nil {
		t.Errorf("on_close_violation record must leave the file: %v", err)
	}

	// The local emergency switch stops the watch.
	if err := os.WriteFile(filepath.Join(cfgDir, OffSwitchFile), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the switch to take effect", func() bool { return e.Health().Mounts == 0 })
	if got := e.Capabilities()[policy.ChannelFileRemovable]; got != "unsupported:disabled_locally" {
		t.Errorf("capability while off: %s", got)
	}
	if err := os.WriteFile(filepath.Join(drive, "while-off.txt"), []byte("TOPSECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	if n := len(sink.events()); n != 1 {
		t.Errorf("%d events while switched off", n)
	}
}

func TestWindowsEnforcer_Quarantines(t *testing.T) {
	drive := fakeDrive(t, winVolume{})
	e, sink, cfgDir := startEnforcer(t, winBundleAction(`, "audit_only": false, "copy_correlation": {"on_close_violation": "quarantine"}`, "block"))
	eventually(t, "the drive to be watched", func() bool { h := e.Health(); return h != nil && h.Mounts == 1 })
	path := filepath.Join(drive, "keys.txt")
	if err := os.WriteFile(path, []byte("TOPSECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the event", func() bool { return len(sink.events()) == 1 })
	if ev := sink.events()[0]; ev.Action != events.ActionQuarantined {
		t.Errorf("action %q would_have %q", ev.Action, ev.WouldHave)
	}
	eventually(t, "the file to be removed", func() bool { _, err := os.Stat(path); return os.IsNotExist(err) })
	q, err := os.ReadDir(filepath.Join(cfgDir, QuarantineDir))
	if err != nil || len(q) != 1 || !strings.HasSuffix(q[0].Name(), "-keys.txt") {
		t.Fatalf("quarantine %v %v", q, err)
	}
	if b, err := os.ReadFile(filepath.Join(cfgDir, QuarantineDir, q[0].Name())); err != nil || string(b) != "TOPSECRET" {
		t.Errorf("quarantined copy %q %v", b, err)
	}
}

func TestWindowsEnforcer_AuditOnlyLeavesFiles(t *testing.T) {
	drive := fakeDrive(t, winVolume{})
	e, sink, _ := startEnforcer(t, winBundleAction(`, "copy_correlation": {"on_close_violation": "delete"}`, "block"))
	eventually(t, "the drive to be watched", func() bool { h := e.Health(); return h != nil && h.Mounts == 1 })
	path := filepath.Join(drive, "keys.txt")
	if err := os.WriteFile(path, []byte("TOPSECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the event", func() bool { return len(sink.events()) == 1 })
	if ev := sink.events()[0]; ev.Action != events.ActionMonitored || ev.WouldHave != events.ActionDeleted {
		t.Errorf("action %q would_have %q", ev.Action, ev.WouldHave)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("audit-only must leave the file: %v", err)
	}
}

func TestWindowsEnforcer_TrustedDeviceNotWatched(t *testing.T) {
	fakeDrive(t, winVolume{Destination: Destination{USB: &events.USB{VendorID: "0781", ProductID: "5567"}}})
	e, _, _ := startEnforcer(t, winBundle(`, "trusted_devices": [{"vendor_id": "0781", "product_id": "5567"}]`))
	time.Sleep(600 * time.Millisecond)
	if h := e.Health(); h == nil || h.Mounts != 0 {
		t.Errorf("a trusted device is watched: %+v", h)
	}
}

// deviceSeams records the device control calls instead of making them.
type deviceSeams struct {
	mu    sync.Mutex
	calls []string
	ro    bool // what volumeReadOnly answers
}

func (d *deviceSeams) install(t *testing.T) {
	t.Helper()
	oldSet, oldRemount, oldRO := setDiskReadOnly, remountVolume, volumeReadOnly
	setDiskReadOnly = func(disk uint32, ro bool) error {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.calls = append(d.calls, "attr:"+map[bool]string{true: "ro", false: "rw"}[ro])
		d.ro = ro
		return nil
	}
	remountVolume = func(string) error { d.mu.Lock(); defer d.mu.Unlock(); d.calls = append(d.calls, "remount"); return nil }
	volumeReadOnly = func(string) bool { d.mu.Lock(); defer d.mu.Unlock(); return d.ro }
	t.Cleanup(func() { setDiskReadOnly, remountVolume, volumeReadOnly = oldSet, oldRemount, oldRO })
}

func (d *deviceSeams) got() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return strings.Join(d.calls, ",")
}

func TestWindowsDevices_ReadOnlyAndRestore(t *testing.T) {
	seams := &deviceSeams{}
	seams.install(t)
	fakeDrive(t, winVolume{DiskNumber: 3})
	e, sink, _ := startEnforcer(t, winBundle(`, "audit_only": false, "copy_correlation": {"untrusted_devices": "read_only"}`))
	eventually(t, "the drive made read-only", func() bool { return seams.got() == "attr:ro,remount" })
	eventually(t, "the device event", func() bool { return len(sink.events()) == 1 })
	if ev := sink.events()[0]; ev.Action != events.ActionBlocked || ev.Scan.Status != StatusNotScanned {
		t.Errorf("event %+v", ev)
	}
	if h := e.Health(); h.Mounts != 0 {
		t.Errorf("a read-only drive is watched: %+v", h)
	}
	e.Stop()
	if got := seams.got(); got != "attr:ro,remount,attr:rw,remount" {
		t.Errorf("not restored on stop: %s", got)
	}
}

func TestWindowsDevices_AuditOnlyRecords(t *testing.T) {
	seams := &deviceSeams{}
	seams.install(t)
	fakeDrive(t, winVolume{DiskNumber: 3})
	_, sink, _ := startEnforcer(t, winBundle(`, "copy_correlation": {"untrusted_devices": "block_writes"}`))
	eventually(t, "the device event", func() bool { return len(sink.events()) == 1 })
	if ev := sink.events()[0]; ev.Action != events.ActionMonitored || ev.WouldHave != events.ActionBlocked {
		t.Errorf("event %+v", ev)
	}
	time.Sleep(500 * time.Millisecond)
	if got := seams.got(); got != "" {
		t.Errorf("audit-only changed the device: %s", got)
	}
	if n := len(sink.events()); n != 1 {
		t.Errorf("recorded %d times", n)
	}
}

func TestWindowsDevices_IgnoredAttributeIsUndone(t *testing.T) {
	seams := &deviceSeams{}
	seams.install(t)
	volumeReadOnly = func(string) bool { return false } // a reader that ignores it
	fakeDrive(t, winVolume{DiskNumber: 3})
	_, sink, _ := startEnforcer(t, winBundle(`, "audit_only": false, "copy_correlation": {"untrusted_devices": "read_only"}`))
	eventually(t, "the attempt", func() bool { return strings.HasPrefix(seams.got(), "attr:ro,remount,attr:rw,remount") })
	if n := len(sink.events()); n != 0 {
		t.Errorf("a failed attempt was recorded as blocked: %d events", n)
	}
}

func TestParseNotify(t *testing.T) {
	rec := func(action uint32, name string, last bool) []byte {
		u := utf16.Encode([]rune(name))
		b := make([]byte, 12+2*len(u))
		binary.LittleEndian.PutUint32(b[4:], action)
		binary.LittleEndian.PutUint32(b[8:], uint32(2*len(u)))
		for i, c := range u {
			binary.LittleEndian.PutUint16(b[12+2*i:], c)
		}
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		if !last {
			binary.LittleEndian.PutUint32(b[0:], uint32(len(b)))
		}
		return b
	}
	var buf []byte
	buf = append(buf, rec(windows.FILE_ACTION_ADDED, `docs\a.txt`, false)...)
	buf = append(buf, rec(windows.FILE_ACTION_REMOVED, "gone.txt", false)...)
	buf = append(buf, rec(windows.FILE_ACTION_RENAMED_OLD_NAME, "~WRL0001.tmp", false)...)
	buf = append(buf, rec(windows.FILE_ACTION_RENAMED_NEW_NAME, "Report é.xlsx", false)...)
	buf = append(buf, rec(windows.FILE_ACTION_MODIFIED, "b.txt", true)...)
	got := strings.Join(parseNotify(buf), "|")
	if want := `docs\a.txt|Report é.xlsx|b.txt`; got != want {
		t.Errorf("got %q want %q", got, want)
	}
	if n := parseNotify(buf[:7]); len(n) != 0 {
		t.Errorf("truncated buffer: %v", n)
	}
}

func TestParseUSBInstanceID(t *testing.T) {
	for id, want := range map[string]string{
		`USB\VID_0781&PID_5567\4C530001234567`: "0781:5567:4C530001234567",
		`USB\VID_090C&PID_1000\6&2C6E3D2&0&2`:  "090c:1000:",
		`USB\VID_0BDA&PID_0129&MI_00\7&1`:      "-",
		`USBSTOR\DISK&VEN_SANDISK\4C53&0`:      "-",
		`USB\ROOT_HUB30\4&1`:                   "-",
	} {
		usb, ok := parseUSBInstanceID(id)
		got := "-"
		if ok {
			got = usb.VendorID + ":" + usb.ProductID + ":" + usb.Serial
		}
		if got != want {
			t.Errorf("%s: got %s want %s", id, got, want)
		}
	}
}

func TestParseBusType(t *testing.T) {
	b := make([]byte, 40)
	binary.LittleEndian.PutUint32(b[28:], busTypeUsb)
	if bus, ok := parseBusType(b); !ok || bus != busTypeUsb {
		t.Errorf("bus %d %v", bus, ok)
	}
	if _, ok := parseBusType(b[:20]); ok {
		t.Error("short descriptor accepted")
	}
}

// The system drive is never a destination, and the queries work without
// admin rights on a real volume.
func TestRemovableVolumes_SystemDriveExcluded(t *testing.T) {
	sys := systemDriveLetter()
	for _, v := range removableVolumes() {
		if strings.EqualFold(v.Mount[:1], sys) {
			t.Errorf("system drive listed: %+v", v)
		}
	}
	h, err := openVolume(sys+`:\`, 0)
	if err != nil {
		t.Skipf("can't open the system volume: %v", err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	if _, ok := busType(h); !ok {
		t.Error("no bus type for the system volume")
	}
}

func TestDevNotifier_Starts(t *testing.T) {
	if err := devNotify.start(); err != nil {
		t.Fatalf("device window: %v", err)
	}
	dir := t.TempDir()
	w, err := startWatch(dir, func(fsChange) {}, func(string) {}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	// A folder on a fixed disk has no device to remove, but registration
	// must still succeed.
	if err := devNotify.register(w.dir, func(bool) {}); err != nil {
		t.Errorf("register: %v", err)
	}
	devNotify.unregister(w.dir)
}

func TestHandleIdentityAndRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.txt")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, _ := windows.UTF16PtrFromString(path)
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(h), path)
	id, err := handleIdentity(h)
	if err != nil || id.Size != 3 || id.Ino == 0 || id.ModTime == 0 || id.ChangeTime == 0 {
		t.Fatalf("identity %+v %v", id, err)
	}
	m := &remediator{dir: t.TempDir(), now: time.Now}
	if err := m.remediate(Request{File: f, Path: path, Ident: id}, policy.ViolationDelete); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("not deleted: %v", err)
	}
	// A changed identity is refused.
	if err := m.sameFile(Request{File: f, Ident: Identity{Dev: 1}}); err == nil {
		t.Error("stale handle accepted")
	}
}
