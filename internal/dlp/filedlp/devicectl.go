//go:build windows || darwin

package filedlp

// The untrusted-device control shared by Windows and macOS
// (copy_correlation.untrusted_devices): which removable volumes must be
// read-only, recording them once, and undoing what the agent did when it no
// longer applies. How a volume is made read-only is the OS's (set); its
// watch is closed first (release), because an open handle or stream on it
// would make the remount fail.

import (
	"log"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
)

// devVolume is a removable volume as the device control sees it.
type devVolume struct {
	Destination        // Source identifies it (a volume GUID path, /dev/disk4s1)
	Disk        uint32 // Windows: the disk number
	ReadOnly    bool   // its file system is read-only now
}

// deviceCtl is the device control's memory, owned by the volume loop (and by
// stopLocked once the loop has ended).
type deviceCtl struct {
	sink    channel.EventSink
	set     func(v devVolume, readOnly bool) error
	release func(mount string)

	madeRO   map[string]devVolume // what the agent made read-only, by Source
	reported map[string]bool      // volumes already recorded
	failed   map[string]bool      // volumes whose change failed (logged once)
}

func newDeviceCtl(sink channel.EventSink, set func(devVolume, bool) error, release func(string)) *deviceCtl {
	return &deviceCtl{sink: sink, set: set, release: release,
		madeRO: map[string]devVolume{}, reported: map[string]bool{}, failed: map[string]bool{}}
}

// madeReadOnly reports whether the agent made the volume read-only.
func (d *deviceCtl) madeReadOnly(source string) bool {
	_, ok := d.madeRO[source]
	return ok
}

// reconcile makes untrusted removable volumes read-only (or records that it
// would, while audit-only), and writable again what no longer needs to be.
// vols are all removable volumes now.
func (d *deviceCtl) reconcile(c *policy.Compiled, vols []devVolume, off bool) {
	present := map[string]bool{}
	for _, v := range vols {
		present[v.Source] = true
	}
	want := untrustedVolumes(c, vols, off)
	d.undo(want, present)
	for src := range d.reported {
		if !present[src] {
			delete(d.reported, src) // unplugged: a new plug-in is recorded again
		}
	}
	for src, v := range want {
		if d.madeReadOnly(src) || v.ReadOnly {
			continue // done already, or read-only anyway (write-protected, mounted so)
		}
		d.apply(c, src, v)
	}
}

// untrustedVolumes are the volumes that must be read-only under c.
func untrustedVolumes(c *policy.Compiled, vols []devVolume, off bool) map[string]devVolume {
	want := map[string]devVolume{}
	if c == nil || off {
		return want
	}
	files := c.Modules.Files
	if files.CopyCorrelation.UntrustedDevices == policy.UntrustedAllow || !files.ChannelEnabled(policy.ChannelFileRemovable) {
		return want
	}
	dests := make([]Destination, 0, len(vols))
	byMount := map[string]devVolume{}
	for _, v := range vols {
		if v.Type == TypeRemovable {
			dests = append(dests, v.Destination)
			byMount[v.Mount] = v
		}
	}
	for _, dest := range untrustedRemovable(c, dests) {
		v := byMount[dest.Mount]
		want[v.Source] = v
	}
	return want
}

// undo makes writable again what the agent made read-only and want no
// longer has; a volume that was unplugged is just forgotten.
func (d *deviceCtl) undo(want map[string]devVolume, present map[string]bool) {
	for src, v := range d.madeRO {
		if _, ok := want[src]; ok {
			continue
		}
		if present[src] {
			d.release(v.Mount)
			if err := d.set(v, false); err != nil {
				log.Printf("DLP: could not make a removable drive writable again: %v", err)
				continue // tried again next pass
			}
		}
		delete(d.madeRO, src)
	}
}

// apply makes one untrusted volume read-only, or records that it would.
func (d *deviceCtl) apply(c *policy.Compiled, src string, v devVolume) {
	if c.Modules.Files.IsAuditOnly() {
		d.report(c, src, v, events.ActionMonitored, events.ActionBlocked)
		return
	}
	d.release(v.Mount)
	if err := d.set(v, true); err != nil {
		if !d.failed[src] {
			d.failed[src] = true
			log.Printf("DLP: could not make an untrusted removable drive read-only: %v", err)
		}
		return
	}
	delete(d.failed, src)
	d.madeRO[src] = v
	d.report(c, src, v, events.ActionBlocked, "")
}

func (d *deviceCtl) report(c *policy.Compiled, src string, v devVolume, action, wouldHave string) {
	if d.reported[src] {
		return
	}
	d.reported[src] = true
	emitDeviceEvent(d.sink, c, v.Destination, action, wouldHave)
}

// restore makes writable again everything the agent made read-only.
func (d *deviceCtl) restore() {
	for src, v := range d.madeRO {
		if err := d.set(v, false); err != nil {
			log.Printf("DLP: could not make a removable drive writable again: %v", err)
		}
		delete(d.madeRO, src)
	}
}
