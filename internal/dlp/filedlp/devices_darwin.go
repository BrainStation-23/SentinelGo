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
	"log"

	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
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

type macDeviceState struct {
	madeRO   map[string]macVolume // device (/dev/disk4s1) → what the agent made read-only
	reported map[string]bool
	failed   map[string]bool
}

func newMacDeviceState() *macDeviceState {
	return &macDeviceState{madeRO: map[string]macVolume{}, reported: map[string]bool{}, failed: map[string]bool{}}
}

// reconcileDevices makes untrusted removable volumes read-only (or records
// that it would, while audit-only), and writable again what no longer needs
// to be. The volume's stream is closed first.
func (e *darwinEnforcer) reconcileDevices(c *policy.Compiled, vols []macVolume, off bool, st *macDeviceState) {
	want := map[string]macVolume{}
	present := map[string]bool{}
	var removable []Destination
	byMount := map[string]macVolume{}
	for _, v := range vols {
		present[v.Source] = true
		if v.Type == TypeRemovable {
			removable = append(removable, v.Destination)
			byMount[v.Mount] = v
		}
	}
	var files policy.FilesModule
	if c != nil {
		files = c.Modules.Files
	}
	if c != nil && !off && files.CopyCorrelation.UntrustedDevices != policy.UntrustedAllow && files.ChannelEnabled(policy.ChannelFileRemovable) {
		for _, d := range untrustedRemovable(c, removable) {
			v := byMount[d.Mount]
			want[v.Source] = v
		}
	}
	for dev, v := range st.madeRO {
		if _, ok := want[dev]; ok {
			continue
		}
		if present[dev] {
			e.releaseWatch(v.Mount)
			if err := remountDevice(dev, false); err != nil {
				log.Printf("DLP: could not make a removable drive writable again: %v", err)
				continue
			}
		}
		delete(st.madeRO, dev)
	}
	for dev := range st.reported {
		if !present[dev] {
			delete(st.reported, dev)
		}
	}
	for dev, v := range want {
		if _, done := st.madeRO[dev]; done || v.ReadOnly {
			continue
		}
		if files.IsAuditOnly() {
			if !st.reported[dev] {
				st.reported[dev] = true
				emitDeviceEvent(e.opts.Sink, c, v.Destination, events.ActionMonitored, events.ActionBlocked)
			}
			continue
		}
		e.releaseWatch(v.Mount)
		if err := remountDevice(dev, true); err != nil {
			if !st.failed[dev] {
				st.failed[dev] = true
				log.Printf("DLP: could not make an untrusted removable drive read-only: %v", err)
			}
			continue
		}
		delete(st.failed, dev)
		st.madeRO[dev] = v
		if !st.reported[dev] {
			st.reported[dev] = true
			emitDeviceEvent(e.opts.Sink, c, v.Destination, events.ActionBlocked, "")
		}
	}
}

func (e *darwinEnforcer) restoreDevices(st *macDeviceState) {
	for dev := range st.madeRO {
		if err := remountDevice(dev, false); err != nil {
			log.Printf("DLP: could not make a removable drive writable again: %v", err)
		}
		delete(st.madeRO, dev)
	}
}
