package filedlp

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
	"sentinelgo/internal/dlp/scanworker"
)

// The test binary doubles as the scan worker.
const workerTestEnv = "SENTINELGO_SCANWORKER_TEST"

func TestMain(m *testing.M) {
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

func macBundle(files, action string) string {
	return `{"schema_version": 1, "version": "v1", "enabled": true,
  "modules": {"files": {"enabled": true, "channels": {"file.removable": true}` + files + `}},
  "policies": [{"id": "p1", "name": "Secrets", "severity": "high", "channels": ["file.removable"], "action": "` + action + `",
    "detectors": [{"id": "custom.keywords", "rule_id": "kw", "min_count": 1, "keywords": ["TOPSECRET"]}]}]}`
}

// fakeMacDrive makes a temp folder play a USB drive (its real path: FSEvents
// reports /private/var/…, not the /var symlink).
func fakeMacDrive(t *testing.T, usb *events.USB) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	vol := macVolume{Destination: Destination{Channel: policy.ChannelFileRemovable, Type: TypeRemovable, Mount: dir,
		VolumeLabel: "TEST", Source: "/dev/disk99s1", USB: usb}}
	listVolumes = func() []macVolume { return []macVolume{vol} }
	workerEnv = []string{workerTestEnv + "=serve"}
	oldQuiet, oldTick, oldPoll := quietFor, pendingTick, volumePoll
	quietFor, pendingTick, volumePoll = 300*time.Millisecond, 50*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() {
		listVolumes, workerEnv = macVolumes, nil
		quietFor, pendingTick, volumePoll = oldQuiet, oldTick, oldPoll
	})
	return dir
}

func startMacEnforcer(t *testing.T, bundle string) (Enforcer, *recordingSink, string) {
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

// writeAs writes from another process: FSEvents ignores the agent's own
// writes (kFSEventStreamCreateFlagIgnoreSelf).
func writeAs(t *testing.T, path, content string) {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", `printf %s "$1" > "$2"`, "sh", content, path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("write: %v %s", err, out)
	}
}

// End to end through real FSEvents (purego) and real sandboxed workers.
func TestDarwinEnforcer_ScansAfterWrite(t *testing.T) {
	drive := fakeMacDrive(t, nil)
	e, sink, cfgDir := startMacEnforcer(t, macBundle("", "monitor"))
	eventually(t, "the drive to be watched", func() bool { h := e.Health(); return h != nil && h.Mounts == 1 })
	if caps := e.Capabilities(); caps[policy.ChannelFileRemovable] != "supported" {
		t.Errorf("caps %v", caps)
	}
	if cc := e.CopyCorrelation(); cc[MethodProcessTaint] != "unsupported:"+esReason || cc[MethodScanOnClose] != "supported" {
		t.Errorf("copy correlation %v", cc)
	}
	writeAs(t, filepath.Join(drive, "clean.txt"), "nothing to see")
	writeAs(t, filepath.Join(drive, "report.txt"), "quarterly TOPSECRET numbers")
	eventually(t, "the event", func() bool { return len(sink.events()) == 1 })
	ev := sink.events()[0]
	if ev.File == nil || ev.File.Name == nil || *ev.File.Name != "report.txt" || ev.Destination.VolumeLabel != "TEST" ||
		ev.Findings[0].Detector != "custom.keywords" {
		t.Errorf("event %+v", ev)
	}
	// The clean file's scan isn't ordered before the other file's event
	// (FSEvents batches, each file waits out its own quiet period): wait
	// for it rather than expect it already done.
	eventually(t, "both files scanned", func() bool { return e.Health().Stats.Scans >= 2 })
	if h := e.Health(); !strings.Contains(h.Workers.Sandbox, "rlimits") {
		t.Errorf("health %+v", h)
	}

	if err := os.WriteFile(filepath.Join(cfgDir, OffSwitchFile), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the switch to take effect", func() bool { return e.Health().Mounts == 0 })
	writeAs(t, filepath.Join(drive, "while-off.txt"), "TOPSECRET")
	time.Sleep(1500 * time.Millisecond)
	if n := len(sink.events()); n != 1 {
		t.Errorf("%d events while switched off", n)
	}
}

func TestDarwinEnforcer_Quarantines(t *testing.T) {
	drive := fakeMacDrive(t, nil)
	e, sink, cfgDir := startMacEnforcer(t, macBundle(`, "audit_only": false, "copy_correlation": {"on_close_violation": "quarantine"}`, "block"))
	eventually(t, "the drive to be watched", func() bool { h := e.Health(); return h != nil && h.Mounts == 1 })
	path := filepath.Join(drive, "keys.txt")
	writeAs(t, path, "TOPSECRET")
	eventually(t, "the event", func() bool { return len(sink.events()) == 1 })
	if ev := sink.events()[0]; ev.Action != events.ActionQuarantined {
		t.Errorf("action %q", ev.Action)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("not removed: %v", err)
	}
	if q, err := os.ReadDir(filepath.Join(cfgDir, QuarantineDir)); err != nil || len(q) != 1 {
		t.Errorf("quarantine %v %v", q, err)
	}
}

func TestDarwinDevices_ReadOnlyAndRestore(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	prev := remountDevice
	remountDevice = func(dev string, ro bool) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, dev+":"+map[bool]string{true: "ro", false: "rw"}[ro])
		return nil
	}
	t.Cleanup(func() { remountDevice = prev })
	got := func() string { mu.Lock(); defer mu.Unlock(); return strings.Join(calls, ",") }
	fakeMacDrive(t, &events.USB{VendorID: "0951", ProductID: "1666"})
	e, sink, _ := startMacEnforcer(t, macBundle(`, "audit_only": false, "copy_correlation": {"untrusted_devices": "read_only"}`, "monitor"))
	eventually(t, "the remount", func() bool { return got() == "/dev/disk99s1:ro" })
	eventually(t, "the device event", func() bool { return len(sink.events()) == 1 })
	if ev := sink.events()[0]; ev.Action != events.ActionBlocked || ev.Scan.Status != StatusNotScanned {
		t.Errorf("event %+v", ev)
	}
	e.Stop()
	if g := got(); g != "/dev/disk99s1:ro,/dev/disk99s1:rw" {
		t.Errorf("not restored on stop: %s", g)
	}
}
