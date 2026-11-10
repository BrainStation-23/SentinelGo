package filedlp

// Strict mode for untrusted removable devices on macOS
// (copy_correlation.untrusted_devices, #332 layer 2): the volume is
// unmounted and mounted again read-only with diskutil. read_only and
// block_writes do the same thing, as on Linux and Windows. diskutil refuses
// to unmount a volume with files open on it; the agent then tries again on
// the next pass rather than forcing it (that would lose a copy in progress).
// What the agent made read-only it mounts writable again when the setting
// goes back to allow, the device becomes trusted, the emergency switch is on
// or monitoring stops. After a crash the volume stays read-only until it is
// plugged in again.

import (
	"context"
	"fmt"
)

// Test seam: the remount.
var remountDevice = func(dev string, readOnly bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), toolTimeout)
	defer cancel()
	if _, err := runDiskutil(ctx, "unmount", dev); err != nil {
		return fmt.Errorf("unmount (files may be open on it): %w", err)
	}
	args := []string{"mount", dev}
	if readOnly {
		args = []string{"mount", "readOnly", dev}
	}
	if _, err := runDiskutil(ctx, args...); err != nil {
		return fmt.Errorf("mount again: %w", err)
	}
	return nil
}

// setReadOnlyDevice is the device control's set on macOS.
func setReadOnlyDevice(v devVolume, readOnly bool) error { return remountDevice(v.Source, readOnly) }

// devVolumes turns the mounts into what the device control uses.
func devVolumes(vols []macVolume) []devVolume {
	out := make([]devVolume, len(vols))
	for i, v := range vols {
		out[i] = devVolume{Destination: v.Destination, ReadOnly: v.ReadOnly}
	}
	return out
}
