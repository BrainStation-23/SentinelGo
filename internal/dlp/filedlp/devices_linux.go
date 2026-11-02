package filedlp

import (
	"log"
	"time"

	"golang.org/x/sys/unix"

	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
)

// Strict mode for untrusted removable devices (copy_correlation.
// untrusted_devices, #334). On Linux read_only and block_writes are the same
// thing: the device's mount is remounted read-only, so nothing can be
// written to it. Only that mount point changes (a bind remount), and its
// other flags (nosuid, nodev, noexec, atime) are kept: dropping nosuid on a
// USB stick would let its set-user-ID programs run with privilege.
//
// What the agent made read-only it makes writable again when the setting
// goes back to allow, the device becomes trusted, the emergency switch is
// on, or monitoring stops. After a crash a stick stays read-only until it is
// plugged in again.

// statvfs f_flag bits (bits/statvfs.h); x/sys/unix doesn't name them.
const (
	stRdonly      = 0x0001
	stNosuid      = 0x0002
	stNodev       = 0x0004
	stNoexec      = 0x0008
	stSynchronous = 0x0010
	stMandlock    = 0x0040
	stNoatime     = 0x0400
	stNodiratime  = 0x0800
	stRelatime    = 0x1000
)

// Test seams: a mount's flags and the remount itself.
var (
	mountFlags = func(mountPoint string) (int64, error) {
		var st unix.Statfs_t
		if err := unix.Statfs(mountPoint, &st); err != nil {
			return 0, err
		}
		return int64(st.Flags), nil
	}
	remountBind = func(mountPoint string, flags uintptr) error {
		return unix.Mount("", mountPoint, "", flags, "")
	}
)

// remountFlags turns statfs flags into mount(2) flags for a bind remount
// that keeps them, read-only or not as asked.
func remountFlags(stFlags int64, readOnly bool) uintptr {
	flags := uintptr(unix.MS_REMOUNT | unix.MS_BIND)
	for st, ms := range map[int64]uintptr{
		stNosuid: unix.MS_NOSUID, stNodev: unix.MS_NODEV, stNoexec: unix.MS_NOEXEC,
		stSynchronous: unix.MS_SYNCHRONOUS, stMandlock: unix.MS_MANDLOCK,
		stNoatime: unix.MS_NOATIME, stNodiratime: unix.MS_NODIRATIME, stRelatime: unix.MS_RELATIME,
	} {
		if stFlags&st != 0 {
			flags |= ms
		}
	}
	if readOnly {
		flags |= unix.MS_RDONLY
	}
	return flags
}

// setReadOnly remounts mountPoint read-only or writable, keeping its flags.
func setReadOnly(mountPoint string, readOnly bool) error {
	st, err := mountFlags(mountPoint)
	if err != nil {
		return err
	}
	return remountBind(mountPoint, remountFlags(st, readOnly))
}

// deviceState is the device control's memory, owned by the mount loop (and
// by stopLocked once the loop has ended).
type deviceState struct {
	madeRO   map[string]Destination // mount points the agent made read-only
	reported map[string]bool        // mount point + source already recorded
	failed   map[string]bool        // mount points whose remount failed (logged once)
}

func newDeviceState() *deviceState {
	return &deviceState{madeRO: map[string]Destination{}, reported: map[string]bool{}, failed: map[string]bool{}}
}

// untrustedRemovable lists removable mounts whose device neither the files
// module nor any removable-channel policy trusts.
func untrustedRemovable(c *policy.Compiled, mounts []Destination) []Destination {
	trusted := append([]policy.Device(nil), c.Modules.Files.TrustedDevices...)
	for _, p := range c.For(policy.ChannelFileRemovable) {
		trusted = append(trusted, p.Exceptions.TrustedDevices...)
	}
	var out []Destination
	for _, d := range mounts {
		if d.Type == TypeRemovable && !TrustedDevice(trusted, d.USB) {
			out = append(out, d)
		}
	}
	return out
}

// reconcileDevices makes untrusted removable mounts read-only (or records
// that it would, while audit-only), and makes writable again what no longer
// needs to be read-only. mounts are all classified removable mounts now.
func (e *linuxEnforcer) reconcileDevices(c *policy.Compiled, mounts []Destination, off bool, st *deviceState) {
	want := map[string]Destination{}
	present := map[string]bool{}
	for _, d := range mounts {
		present[d.Mount+"\x00"+d.Source] = true
	}
	var files policy.FilesModule
	if c != nil {
		files = c.Modules.Files
	}
	mode := files.CopyCorrelation.UntrustedDevices
	if c != nil && !off && mode != policy.UntrustedAllow && files.ChannelEnabled(policy.ChannelFileRemovable) {
		for _, d := range untrustedRemovable(c, mounts) {
			want[d.Mount] = d
		}
	}
	for mp := range st.madeRO {
		if _, ok := want[mp]; !ok {
			if err := setReadOnly(mp, false); err != nil {
				log.Printf("DLP: could not make a removable drive writable again: %v", errnoOnly(err))
			}
			delete(st.madeRO, mp)
		}
	}
	for key := range st.reported {
		if !present[key] {
			delete(st.reported, key) // unplugged: a new plug-in is recorded again
		}
	}
	for mp, d := range want {
		key := mp + "\x00" + d.Source
		flags, err := mountFlags(mp)
		if err != nil {
			continue
		}
		if flags&stRdonly != 0 {
			continue // read-only already: by us, or write-protected, or mounted so
		}
		if files.IsAuditOnly() {
			if !st.reported[key] {
				st.reported[key] = true
				e.emitDeviceEvent(c, d, events.ActionMonitored, events.ActionBlocked)
			}
			continue
		}
		if err := remountBind(mp, remountFlags(flags, true)); err != nil {
			if !st.failed[mp] {
				st.failed[mp] = true
				log.Printf("DLP: could not make an untrusted removable drive read-only: %v", errnoOnly(err))
			}
			continue
		}
		delete(st.failed, mp)
		st.madeRO[mp] = d
		if !st.reported[key] {
			st.reported[key] = true
			e.emitDeviceEvent(c, d, events.ActionBlocked, "")
		}
	}
}

// restoreDevices makes writable again everything the agent made read-only.
func restoreDevices(st *deviceState) {
	for mp := range st.madeRO {
		if err := setReadOnly(mp, false); err != nil {
			log.Printf("DLP: could not make a removable drive writable again: %v", errnoOnly(err))
		}
		delete(st.madeRO, mp)
	}
}

// emitDeviceEvent records that an untrusted device was made read-only (or
// would have been). No file was read: scan.status is not_scanned and there
// is no hash, as the contract allows for a block by device.
func (e *linuxEnforcer) emitDeviceEvent(c *policy.Compiled, d Destination, action, wouldHave string) {
	if e.opts.Sink == nil {
		return
	}
	e.opts.Sink.Emit(events.Event{
		EventID:       events.NewID(),
		OccurredAt:    time.Now().UTC(),
		Channel:       policy.ChannelFileRemovable,
		PolicyVersion: c.Version,
		Action:        action,
		WouldHave:     wouldHave,
		Severity:      "medium",
		Findings:      []events.Finding{},
		RepeatCount:   1,
		File:          &events.File{},
		Destination:   &events.Destination{Type: TypeRemovable, VolumeLabel: d.VolumeLabel, USB: d.USB},
		Scan:          &events.Scan{Status: StatusNotScanned, VerdictSource: "scan"},
	})
}

// StatusNotScanned is the scan status of a write blocked by device: no file
// was read.
const StatusNotScanned = "not_scanned"
