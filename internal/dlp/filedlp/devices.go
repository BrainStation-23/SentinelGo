package filedlp

import (
	"time"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
)

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

// emitDeviceEvent records that an untrusted device was made read-only (or
// would have been). No file was read: scan.status is not_scanned and there
// is no hash, as the contract allows for a block by device.
func emitDeviceEvent(sink channel.EventSink, c *policy.Compiled, d Destination, action, wouldHave string) {
	if sink == nil {
		return
	}
	sink.Emit(events.Event{
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
