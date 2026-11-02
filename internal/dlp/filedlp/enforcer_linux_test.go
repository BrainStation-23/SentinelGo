package filedlp

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"sentinelgo/internal/dlp/policy"
	"sentinelgo/internal/dlp/scanworker"
)

// The test binary doubles as the scan worker.
const workerTestEnv = "SENTINELGO_SCANWORKER_TEST"

func TestMain(m *testing.M) {
	switch os.Getenv(workerTestEnv) {
	case "serve":
		if err := scanworker.Serve(); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	case "hang": // says hello, then never answers a scan
		hello := []byte(`{"type":"ready","sandbox":"test"}`)
		f := os.NewFile(3, "s")
		_, _ = f.Write(append([]byte{0, 0, 0, byte(len(hello))}, hello...))
		time.Sleep(time.Hour)
	}
	os.Exit(m.Run())
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

const enforcerBundle = `{"schema_version": 1, "version": "v1", "enabled": true,
  "modules": {"files": {"enabled": true, "channels": {"file.removable": true}}},
  "policies": [{"id": "p1", "name": "Secrets", "severity": "high", "channels": ["file.removable"], "action": "monitor",
    "detectors": [{"id": "custom.keywords", "rule_id": "kw", "min_count": 1, "keywords": ["TOPSECRET"]}]}]}`

// fakeStick mounts a tmpfs that plays a USB stick and makes the enforcer's
// workers run the given test mode. Needs root (to mount, and for fanotify).
func fakeStick(t *testing.T, workerMode string) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: mounts a tmpfs and uses fanotify")
	}
	stick := t.TempDir()
	if err := unix.Mount("tmpfs", stick, "tmpfs", 0, "size=16m,mode=0777"); err != nil {
		t.Skipf("can't mount a tmpfs here: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(stick, unix.MNT_DETACH) })
	classifyMount = func(m mountInfo, _ map[string]string) (Destination, bool) {
		if m.MountPoint != stick {
			return Destination{}, false
		}
		return Destination{Channel: policy.ChannelFileRemovable, Type: TypeRemovable, Mount: stick, VolumeLabel: "TEST"}, true
	}
	workerEnv = []string{workerTestEnv + "=" + workerMode}
	t.Cleanup(func() { classifyMount, workerEnv = classify, nil })
	return stick
}

// writeAs writes a file from another process: the enforcer ignores the
// agent's own writes.
func writeAs(t *testing.T, dir, name, content string) {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", `printf %s "$1" > "$2"`, "sh", content, filepath.Join(dir, name))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("write %s: %v %s", name, err, out)
	}
}

// End to end on a real kernel: a tmpfs plays the USB stick. Run in a
// privileged container or VM.
func TestEnforcer_EndToEnd(t *testing.T) {
	stick := fakeStick(t, "serve")
	exe := testExe(t)
	sink := &recordingSink{}
	cfgDir := t.TempDir()
	e := New(Options{Sink: sink, Exe: exe, ConfigDir: cfgDir})
	e.Apply(context.Background(), compile(t, enforcerBundle))
	t.Cleanup(e.Stop)
	if h := e.Health(); h == nil || h.State != stateRunning {
		t.Skipf("fanotify not available here: %+v", h)
	}
	eventually(t, "the stick to be watched", func() bool { return e.Health().Mounts == 1 })
	if caps := e.Capabilities(); caps[policy.ChannelFileRemovable] != "supported" {
		t.Errorf("caps %v", caps)
	}

	write := func(name, content string) { t.Helper(); writeAs(t, stick, name, content) }
	write("clean.txt", "nothing to see")
	write("report.txt", "quarterly TOPSECRET numbers")
	eventually(t, "the event", func() bool { return len(sink.events()) == 1 })
	ev := sink.events()[0]
	if ev.Channel != policy.ChannelFileRemovable || ev.File == nil || *ev.File.Name != "report.txt" || ev.Destination.VolumeLabel != "TEST" ||
		ev.User != "root" || ev.Process == nil || ev.Findings[0].Detector != "custom.keywords" {
		t.Errorf("event %+v file %+v process %+v", ev, ev.File, ev.Process)
	}
	// The writer (sh) has usually exited by now, so only its name may be
	// known; the user then comes from the file's owner.
	if n := ev.Process.Name; n != "" && n != "sh" {
		t.Errorf("process %q", n)
	}
	if h := e.Health(); !strings.Contains(h.Workers.Sandbox, "no_new_privs") || h.Stats.Scans < 1 {
		t.Errorf("health %+v", h)
	}

	// The local emergency switch removes the marks.
	if err := os.WriteFile(filepath.Join(cfgDir, OffSwitchFile), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the switch to take effect", func() bool { return e.Health().Mounts == 0 })
	if got := e.Capabilities()[policy.ChannelFileRemovable]; got != "unsupported:disabled_locally" {
		t.Errorf("capability while off: %s", got)
	}
	write("while-off.txt", "TOPSECRET")
	time.Sleep(time.Second)
	if n := len(sink.events()); n != 1 {
		t.Errorf("%d events while switched off", n)
	}
	if err := os.Remove(filepath.Join(cfgDir, OffSwitchFile)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "watching again", func() bool { return e.Health().Mounts == 1 })
	write("after.txt", "TOPSECRET again")
	eventually(t, "the second event", func() bool { return len(sink.events()) == 2 })

	// A policy without file channels stops the hook.
	e.Apply(context.Background(), compile(t, strings.Replace(enforcerBundle, `"file.removable": true`, `"file.removable": false`, 1)))
	if h := e.Health(); h.State != stateStopped || h.Mounts != 0 || h.Workers.Workers != 0 {
		t.Errorf("after the channel was turned off: %+v", h)
	}
}

// The agent's own writes never produce events (self-exclusion, #329).
func TestEnforcer_IgnoresOwnWrites(t *testing.T) {
	e := New(Options{}).(*linuxEnforcer)
	e.dests.Store(&[]Destination{{Channel: policy.ChannelFileRemovable, Mount: "/media/x"}})
	queue := make(chan Request, 1)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	fd, err := unix.Dup(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	e.handleEvent(unix.FAN_CLOSE_WRITE, fd, os.Getpid(), os.Getpid(), queue)
	if len(queue) != 0 {
		t.Error("own write queued")
	}
	if err := unix.Close(fd); err == nil {
		t.Error("event descriptor left open")
	}
	e.handleEvent(unix.FAN_Q_OVERFLOW, -1, 0, os.Getpid(), queue)
	e.handleEvent(unix.FAN_CLOSE_WRITE, -1, 7, os.Getpid(), queue)
	if e.overflows.Load() != 1 || e.unreadable.Load() != 1 {
		t.Errorf("overflows %d unreadable %d", e.overflows.Load(), e.unreadable.Load())
	}
}

// Stopping while a scan is in flight returns at once: the scan is cut off
// instead of the stop waiting for it (or deadlocking).
func TestEnforcer_StopDuringScan(t *testing.T) {
	stick := fakeStick(t, "hang")
	exe := testExe(t)
	e := New(Options{Sink: &recordingSink{}, Exe: exe, ConfigDir: t.TempDir()})
	e.Apply(context.Background(), compile(t, enforcerBundle))
	if h := e.Health(); h == nil || h.State != stateRunning {
		e.Stop()
		t.Skipf("fanotify not available here: %+v", h)
	}
	eventually(t, "the stick to be watched", func() bool { return e.Health().Mounts == 1 })
	writeAs(t, stick, "a.txt", "TOPSECRET")
	eventually(t, "a scan in flight", func() bool { return e.Health().Workers.Workers == 1 })
	done := make(chan struct{})
	go func() { e.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop hung while a scan was in flight")
	}
}
