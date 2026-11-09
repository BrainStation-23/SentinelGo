package filedlp

// Strict mode for untrusted removable devices on Windows
// (copy_correlation.untrusted_devices, #330/#334). read_only and
// block_writes do the same thing, as on Linux: the disk is made read-only
// (IOCTL_DISK_SET_DISK_ATTRIBUTES, not persisted) and its volume is
// remounted so the file system sees it. This is prevention by device, not
// by content: nothing can be written to the drive at all.
//
// The remount needs the volume lock. When a program has files open on the
// drive, the lock fails and the agent tries again on the next pass instead
// of forcing a dismount (that would lose a copy in progress). Not persisting
// the attribute means it is gone when the drive is plugged in again, so a
// crashed agent can't leave a stick read-only for good; the agent also
// makes it writable again when the setting goes back to allow, the device
// becomes trusted, the emergency switch is on or monitoring stops.

import (
	"fmt"
	"log"
	"unsafe"

	"golang.org/x/sys/windows"

	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
)

const (
	ioctlDiskSetDiskAttributes = 0x0007C0F4
	diskAttributeReadOnly      = 0x2
	fsctlLockVolume            = 0x00090018
	fsctlUnlockVolume          = 0x0009001C
	fsctlDismountVolume        = 0x00090020
)

// setDiskAttributes is SET_DISK_ATTRIBUTES.
type setDiskAttributes struct {
	Version        uint32
	Persist        byte
	_              [3]byte
	Attributes     uint64
	AttributesMask uint64
	_              [4]uint32
}

// Test seams: the disk attribute and the remount.
var (
	setDiskReadOnly = setDiskReadOnlyIOCTL
	remountVolume   = remountVolumeFSCTL
	volumeReadOnly  = func(root string) bool {
		v, ok := describeVolumeFlags(root)
		return ok && v
	}
)

// setDiskReadOnlyIOCTL sets or clears PhysicalDriveN's read-only attribute.
func setDiskReadOnlyIOCTL(disk uint32, readOnly bool) error {
	p, err := windows.UTF16PtrFromString(fmt.Sprintf(`\\.\PhysicalDrive%d`, disk))
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return fmt.Errorf("open the disk: %w", err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	in := setDiskAttributes{AttributesMask: diskAttributeReadOnly}
	in.Version = uint32(unsafe.Sizeof(in))
	if readOnly {
		in.Attributes = diskAttributeReadOnly
	}
	var n uint32
	if err := windows.DeviceIoControl(h, ioctlDiskSetDiskAttributes, (*byte)(unsafe.Pointer(&in)), in.Version, nil, 0, &n, nil); err != nil {
		return fmt.Errorf("set the disk read-only attribute: %w", err)
	}
	return nil
}

// remountVolumeFSCTL locks and dismounts root's volume so its file system
// mounts again (with the disk's new attribute) on the next access. It fails
// without dismounting when files are open on it.
func remountVolumeFSCTL(root string) error {
	h, err := openVolume(root, windows.GENERIC_READ|windows.GENERIC_WRITE)
	if err != nil {
		return fmt.Errorf("open the volume: %w", err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var n uint32
	if err := windows.DeviceIoControl(h, fsctlLockVolume, nil, 0, nil, 0, &n, nil); err != nil {
		return fmt.Errorf("lock the volume (files are open on it): %w", err)
	}
	defer func() { _ = windows.DeviceIoControl(h, fsctlUnlockVolume, nil, 0, nil, 0, &n, nil) }()
	if err := windows.DeviceIoControl(h, fsctlDismountVolume, nil, 0, nil, 0, &n, nil); err != nil {
		return fmt.Errorf("dismount the volume: %w", err)
	}
	return nil
}

// describeVolumeFlags reports whether root's file system is read-only now.
func describeVolumeFlags(root string) (readOnly, ok bool) {
	p, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return false, false
	}
	var flags uint32
	if windows.GetVolumeInformation(p, nil, 0, nil, nil, &flags, nil, 0) != nil {
		return false, false
	}
	return flags&windows.FILE_READ_ONLY_VOLUME != 0, true
}

// winDeviceState is the device control's memory, owned by the volume loop
// (and by stopLocked once the loop has ended).
type winDeviceState struct {
	madeRO   map[string]winVolume // volume (GUID path) → what the agent made read-only
	reported map[string]bool      // volume already recorded
	failed   map[string]bool      // volume whose change failed (logged once)
}

func newWinDeviceState() *winDeviceState {
	return &winDeviceState{madeRO: map[string]winVolume{}, reported: map[string]bool{}, failed: map[string]bool{}}
}

// setReadOnlyVolume sets the disk attribute and remounts. When making a
// drive read-only fails to remount, the attribute is cleared again, so the
// drive isn't left half-changed. Making it writable keeps the attribute
// cleared even then (fail open): the file system picks it up on its next
// mount at the latest.
func setReadOnlyVolume(v winVolume, readOnly bool) error {
	if err := setDiskReadOnly(v.DiskNumber, readOnly); err != nil {
		return err
	}
	if err := remountVolume(v.Mount); err != nil {
		if readOnly {
			_ = setDiskReadOnly(v.DiskNumber, false)
		}
		return err
	}
	return nil
}

// reconcileDevices makes untrusted removable volumes read-only (or records
// that it would, while audit-only), and makes writable again what no longer
// needs to be read-only. vols are all removable volumes now. The volume's
// watch is closed first: its handle would make the volume lock fail.
func (e *windowsEnforcer) reconcileDevices(c *policy.Compiled, vols []winVolume, off bool, st *winDeviceState) {
	want := map[string]winVolume{}
	present := map[string]bool{}
	for _, v := range vols {
		present[v.Source] = true
	}
	var files policy.FilesModule
	if c != nil {
		files = c.Modules.Files
	}
	mode := files.CopyCorrelation.UntrustedDevices
	if c != nil && !off && mode != policy.UntrustedAllow && files.ChannelEnabled(policy.ChannelFileRemovable) {
		dests := make([]Destination, len(vols))
		byMount := map[string]winVolume{}
		for i, v := range vols {
			dests[i] = v.Destination
			byMount[v.Mount] = v
		}
		for _, d := range untrustedRemovable(c, dests) {
			v := byMount[d.Mount]
			want[v.Source] = v
		}
	}
	for src, v := range st.madeRO {
		if _, ok := want[src]; ok {
			continue
		}
		if present[src] {
			e.releaseWatch(v.Mount)
			if err := setReadOnlyVolume(v, false); err != nil {
				log.Printf("DLP: could not make a removable drive writable again: %v", err)
				continue // tried again next pass
			}
		}
		delete(st.madeRO, src) // writable again, or unplugged (the attribute went with it)
	}
	for src := range st.reported {
		if !present[src] {
			delete(st.reported, src) // unplugged: a new plug-in is recorded again
		}
	}
	for src, v := range want {
		if _, done := st.madeRO[src]; done {
			continue
		}
		if v.ReadOnly {
			continue // read-only already: write-protected, or mounted so
		}
		if files.IsAuditOnly() {
			if !st.reported[src] {
				st.reported[src] = true
				emitDeviceEvent(e.opts.Sink, c, v.Destination, events.ActionMonitored, events.ActionBlocked)
			}
			continue
		}
		e.releaseWatch(v.Mount)
		err := setReadOnlyVolume(v, true)
		if err == nil && !volumeReadOnly(v.Mount) {
			// Some readers and odd controllers ignore the attribute.
			_ = setReadOnlyVolume(v, false)
			err = fmt.Errorf("the device ignores the read-only attribute")
		}
		if err != nil {
			if !st.failed[src] {
				st.failed[src] = true
				log.Printf("DLP: could not make an untrusted removable drive read-only: %v", err)
			}
			continue
		}
		delete(st.failed, src)
		st.madeRO[src] = v
		if !st.reported[src] {
			st.reported[src] = true
			emitDeviceEvent(e.opts.Sink, c, v.Destination, events.ActionBlocked, "")
		}
	}
}

// restoreDevices makes writable again everything the agent made read-only.
func (e *windowsEnforcer) restoreDevices(st *winDeviceState) {
	for src, v := range st.madeRO {
		if err := setReadOnlyVolume(v, false); err != nil {
			log.Printf("DLP: could not make a removable drive writable again: %v", err)
		}
		delete(st.madeRO, src)
	}
}
