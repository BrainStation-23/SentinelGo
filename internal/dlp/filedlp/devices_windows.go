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
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
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

// setReadOnlyVolume sets the disk attribute and remounts. When making a
// drive read-only fails to remount, the attribute is cleared again, so the
// drive isn't left half-changed. Making it writable keeps the attribute
// cleared even then (fail open): the file system picks it up on its next
// mount at the latest. A drive that ignores the attribute (some readers and
// odd controllers do) is put back and reported as a failure.
func setReadOnlyVolume(v devVolume, readOnly bool) error {
	if err := setDiskReadOnly(v.Disk, readOnly); err != nil {
		return err
	}
	if err := remountVolume(v.Mount); err != nil {
		if readOnly {
			_ = setDiskReadOnly(v.Disk, false)
		}
		return err
	}
	if readOnly && !volumeReadOnly(v.Mount) {
		_ = setReadOnlyVolume(v, false)
		return errors.New("the device ignores the read-only attribute")
	}
	return nil
}

// devVolumes turns the removable volumes into what the device control uses.
func devVolumes(vols []winVolume) []devVolume {
	out := make([]devVolume, len(vols))
	for i, v := range vols {
		out[i] = devVolume{Destination: v.Destination, Disk: v.DiskNumber, ReadOnly: v.ReadOnly}
	}
	return out
}
