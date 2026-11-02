package filedlp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
)

func TestRemountFlags(t *testing.T) {
	f := remountFlags(stNosuid|stNodev|stNoexec|stRelatime, true)
	for _, want := range []uintptr{unix.MS_REMOUNT, unix.MS_BIND, unix.MS_RDONLY, unix.MS_NOSUID, unix.MS_NODEV, unix.MS_NOEXEC, unix.MS_RELATIME} {
		if f&want == 0 {
			t.Errorf("flag %#x missing from %#x", want, f)
		}
	}
	if w := remountFlags(stNosuid|stRdonly, false); w&unix.MS_RDONLY != 0 || w&unix.MS_NOSUID == 0 {
		t.Errorf("writable remount %#x", w)
	}
}

// fakeMountTable replaces the mount flag reads and remounts with a table.
type fakeMountTable struct {
	flags    map[string]int64
	remounts []string
	fail     bool
}

func installFakeMountTable(t *testing.T, flags map[string]int64) *fakeMountTable {
	t.Helper()
	ft := &fakeMountTable{flags: flags}
	prevFlags, prevRemount := mountFlags, remountBind
	mountFlags = func(mp string) (int64, error) {
		f, ok := ft.flags[mp]
		if !ok {
			return 0, errors.New("no such mount")
		}
		return f, nil
	}
	remountBind = func(mp string, flags uintptr) error {
		if ft.fail {
			return unix.EBUSY
		}
		ro := flags&unix.MS_RDONLY != 0
		ft.remounts = append(ft.remounts, mp+map[bool]string{true: " ro", false: " rw"}[ro])
		f := ft.flags[mp] &^ stRdonly
		if ro {
			f |= stRdonly
		}
		if flags&unix.MS_NOSUID == 0 {
			f &^= stNosuid // a remount that drops nosuid would show here
		}
		ft.flags[mp] = f
		return nil
	}
	t.Cleanup(func() { mountFlags, remountBind = prevFlags, prevRemount })
	return ft
}

func devBundle(auditOnly bool, mode, trustedModule, trustedPolicy string) string {
	return `{"schema_version": 1, "version": "v1", "enabled": true,
	  "modules": {"files": {"enabled": true, "channels": {"file.removable": true}, "audit_only": ` + map[bool]string{true: "true", false: "false"}[auditOnly] + `,
	    "trusted_devices": [` + trustedModule + `], "copy_correlation": {"untrusted_devices": "` + mode + `"}}},
	  "policies": [{"id": "p1", "name": "n", "channels": ["file.removable"], "action": "monitor",
	    "detectors": [{"id": "pii.credit_card", "rule_id": "r", "min_count": 1}], "exceptions": {"trusted_devices": [` + trustedPolicy + `]}}]}`
}

func TestReconcileDevices(t *testing.T) {
	stick := Destination{Channel: policy.ChannelFileRemovable, Type: TypeRemovable, Mount: "/media/a/STICK", Source: "/dev/sdb1",
		VolumeLabel: "STICK", USB: &events.USB{VendorID: "0951", ProductID: "1666", Serial: "S1"}}
	ours := Destination{Channel: policy.ChannelFileRemovable, Type: TypeRemovable, Mount: "/media/a/OURS", Source: "/dev/sdc1",
		USB: &events.USB{VendorID: "1111", ProductID: "2222"}}
	share := Destination{Channel: policy.ChannelFileNetworkShare, Type: TypeNetworkShare, Mount: "/mnt/share"}
	all := []Destination{stick, ours, share}
	ft := installFakeMountTable(t, map[string]int64{stick.Mount: stNosuid | stNodev, ours.Mount: stNosuid, share.Mount: 0})
	sink := &recordingSink{}
	e := New(Options{Sink: sink}).(*linuxEnforcer)
	st := newDeviceState()
	trustOurs := `{"vendor_id": "1111", "product_id": "2222"}`

	// Read-only for the untrusted stick only; nosuid kept; one blocked event.
	c := compile(t, devBundle(false, "read_only", trustOurs, ""))
	e.reconcileDevices(c, all, false, st)
	e.reconcileDevices(c, all, false, st)
	if strings.Join(ft.remounts, ",") != stick.Mount+" ro" || ft.flags[stick.Mount]&stNosuid == 0 {
		t.Fatalf("remounts %v flags %#x", ft.remounts, ft.flags[stick.Mount])
	}
	evs := sink.events()
	if len(evs) != 1 || evs[0].Action != events.ActionBlocked || evs[0].Scan.Status != StatusNotScanned ||
		evs[0].Destination.USB.Serial != "S1" || evs[0].File == nil || evs[0].File.SHA256 != "" || evs[0].PolicyID != "" {
		t.Fatalf("events %+v", evs)
	}
	// Trusted by a policy's exception: left alone too.
	ft2 := installFakeMountTable(t, map[string]int64{stick.Mount: 0, ours.Mount: 0})
	e.reconcileDevices(compile(t, devBundle(false, "block_writes", "", trustOurs)), []Destination{ours}, false, newDeviceState())
	if len(ft2.remounts) != 0 {
		t.Errorf("a policy-trusted device was remounted: %v", ft2.remounts)
	}
	mountFlags, remountBind = func(mp string) (int64, error) { return ft.flags[mp], nil }, func(mp string, f uintptr) error {
		ft.remounts = append(ft.remounts, mp+map[bool]string{true: " ro", false: " rw"}[f&unix.MS_RDONLY != 0])
		if f&unix.MS_RDONLY == 0 {
			ft.flags[mp] &^= stRdonly
		}
		return nil
	}

	// Back to allow: writable again, nosuid still there.
	e.reconcileDevices(compile(t, devBundle(false, "allow", trustOurs, "")), all, false, st)
	if last := ft.remounts[len(ft.remounts)-1]; last != stick.Mount+" rw" || len(st.madeRO) != 0 {
		t.Errorf("not restored: %v", ft.remounts)
	}

	// Audit-only: nothing remounted, one monitored event with would_have.
	sink2 := &recordingSink{}
	e2 := New(Options{Sink: sink2}).(*linuxEnforcer)
	n := len(ft.remounts)
	st2 := newDeviceState()
	for i := 0; i < 2; i++ {
		e2.reconcileDevices(compile(t, devBundle(true, "read_only", trustOurs, "")), all, false, st2)
	}
	if len(ft.remounts) != n {
		t.Errorf("audit-only remounted: %v", ft.remounts[n:])
	}
	if evs := sink2.events(); len(evs) != 1 || evs[0].Action != events.ActionMonitored || evs[0].WouldHave != events.ActionBlocked {
		t.Errorf("audit-only events %+v", evs)
	}
	// Unplugged and plugged in again: recorded again.
	e2.reconcileDevices(compile(t, devBundle(true, "read_only", trustOurs, "")), nil, false, st2)
	e2.reconcileDevices(compile(t, devBundle(true, "read_only", trustOurs, "")), all, false, st2)
	if len(sink2.events()) != 2 {
		t.Errorf("replug not recorded: %d", len(sink2.events()))
	}
}

func TestReconcileDevices_OffSwitchAndFailures(t *testing.T) {
	stick := Destination{Channel: policy.ChannelFileRemovable, Type: TypeRemovable, Mount: "/media/a/STICK", Source: "/dev/sdb1"}
	ft := installFakeMountTable(t, map[string]int64{stick.Mount: 0})
	sink := &recordingSink{}
	e := New(Options{Sink: sink}).(*linuxEnforcer)
	st := newDeviceState()
	c := compile(t, devBundle(false, "read_only", "", ""))
	e.reconcileDevices(c, []Destination{stick}, false, st)
	// The emergency switch makes it writable again.
	e.reconcileDevices(c, []Destination{stick}, true, st)
	if strings.Join(ft.remounts, ",") != stick.Mount+" ro,"+stick.Mount+" rw" {
		t.Errorf("remounts %v", ft.remounts)
	}
	// A failed remount: no event claims a block.
	ft2 := installFakeMountTable(t, map[string]int64{stick.Mount: 0})
	ft2.fail = true
	sink2 := &recordingSink{}
	e2 := New(Options{Sink: sink2}).(*linuxEnforcer)
	e2.reconcileDevices(c, []Destination{stick}, false, newDeviceState())
	if len(sink2.events()) != 0 {
		t.Errorf("event for a failed remount: %+v", sink2.events())
	}
	// Already read-only (write-protected): left alone, no event.
	ft3 := installFakeMountTable(t, map[string]int64{stick.Mount: stRdonly})
	sink3 := &recordingSink{}
	e3 := New(Options{Sink: sink3}).(*linuxEnforcer)
	e3.reconcileDevices(c, []Destination{stick}, false, newDeviceState())
	if len(ft3.remounts) != 0 || len(sink3.events()) != 0 {
		t.Errorf("write-protected stick: %v %v", ft3.remounts, sink3.events())
	}
	// restoreDevices undoes everything.
	ft4 := installFakeMountTable(t, map[string]int64{stick.Mount: 0})
	st4 := newDeviceState()
	e.reconcileDevices(c, []Destination{stick}, false, st4)
	restoreDevices(st4)
	if len(st4.madeRO) != 0 || ft4.flags[stick.Mount]&stRdonly != 0 {
		t.Errorf("not restored: %v", ft4.remounts)
	}
}

// End to end as root: an untrusted "stick" (a tmpfs mounted nosuid,nodev)
// becomes read-only with its flags kept, the event is recorded, and turning
// the mode off or stopping makes it writable again.
func TestEnforcer_UntrustedDeviceEndToEnd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: mounts a tmpfs")
	}
	stick := t.TempDir()
	if err := unix.Mount("tmpfs", stick, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "size=4m,mode=0777"); err != nil {
		t.Skipf("can't mount a tmpfs here: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(stick, unix.MNT_DETACH) })
	prevClassify := classifyMount
	classifyMount = func(m mountInfo, _ map[string]string) (Destination, bool) {
		if m.MountPoint != stick {
			return Destination{}, false
		}
		return Destination{Channel: policy.ChannelFileRemovable, Type: TypeRemovable, Mount: stick, Source: "tmpfs",
			USB: &events.USB{VendorID: "dead", ProductID: "beef"}}, true
	}
	prevInit, prevMark := fanotifyInit, markMount
	fanotifyInit = func() (int, error) { // device control needs no fanotify marks here
		var p [2]int
		if err := unix.Pipe2(p[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
			return -1, err
		}
		return p[0], nil
	}
	markMount = func(int, bool, string) error { return nil }
	t.Cleanup(func() { classifyMount, fanotifyInit, markMount = prevClassify, prevInit, prevMark })

	sink := &recordingSink{}
	e := New(Options{Sink: sink, ConfigDir: t.TempDir()})
	bundle := strings.Replace(devBundle(false, "read_only", "", ""), `"untrusted_devices": "read_only"`, `"untrusted_devices": "read_only", "scan_on_close": false`, 1)
	e.Apply(context.Background(), compile(t, bundle))
	t.Cleanup(e.Stop)
	probe := filepath.Join(stick, "probe.txt")
	eventually(t, "the stick to become read-only", func() bool {
		return os.WriteFile(probe, []byte("x"), 0o600) != nil
	})
	var st unix.Statfs_t
	if err := unix.Statfs(stick, &st); err != nil || st.Flags&stNosuid == 0 || st.Flags&stNodev == 0 || st.Flags&stRdonly == 0 {
		t.Errorf("flags %#x %v: nosuid/nodev must be kept", st.Flags, err)
	}
	eventually(t, "the event", func() bool { return len(sink.events()) == 1 })
	if ev := sink.events()[0]; ev.Action != events.ActionBlocked || ev.Scan.Status != StatusNotScanned {
		t.Errorf("event %+v", ev)
	}
	if cc := e.CopyCorrelation(); cc[MethodUntrustedDevices] != "supported" {
		t.Errorf("capability %v", cc)
	}
	// Mode off: writable again.
	e.Apply(context.Background(), compile(t, strings.Replace(bundle, `"untrusted_devices": "read_only"`, `"untrusted_devices": "allow"`, 1)))
	eventually(t, "the stick to be writable again", func() bool { return os.WriteFile(probe, []byte("x"), 0o600) == nil })
	// On again, then Stop: writable again (fail open).
	e.Apply(context.Background(), compile(t, bundle))
	eventually(t, "read-only again", func() bool { return os.WriteFile(probe, []byte("y"), 0o600) != nil })
	e.Stop()
	if err := os.WriteFile(probe, []byte("z"), 0o600); err != nil {
		t.Errorf("still read-only after Stop: %v", err)
	}
}
