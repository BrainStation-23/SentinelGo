// Package volumes implements the telemetry Volumes collector, filling the
// "volumes" section — the mount-point/filesystem/capacity half of the
// physical-disk/volume split docs/telemetry/02-gap-analysis.md calls for,
// complementing the physicaldisks collector which owns the device half.
package volumes

import (
	"context"
	"sort"

	tel "sentinelgo/internal/telemetry"
)

// Name is the collector's identifier, also used as its section name.
const Name = tel.SectionVolumes

// Volume describes one mounted filesystem.
type Volume struct {
	MountPoint string `json:"mount_point,omitempty"`
	// DriveLetter is Windows-only ("C:", "D:", ...) and empty elsewhere.
	DriveLetter string `json:"drive_letter,omitempty"`
	Label       string `json:"label,omitempty"`
	FileSystem  string `json:"file_system,omitempty"`
	SizeBytes   uint64 `json:"size_bytes"`
	FreeBytes   uint64 `json:"free_bytes"`
}

// Payload is the wire shape of the "volumes" section.
type Payload struct {
	Volumes []Volume `json:"volumes"`
}

// signal is what platform code supplies before assembling Payload.
type signal struct {
	Volumes  []Volume
	Err      error
	Source   string
	Warnings []string
}

// Collector implements telemetry.Collector for volume/filesystem inventory.
type Collector struct{}

// New returns the Volumes collector.
func New() *Collector { return &Collector{} }

func (c *Collector) Name() string       { return Name }
func (c *Collector) Section() string    { return tel.SectionVolumes }
func (c *Collector) SchemaVersion() int { return 1 }

// Capability reports volume enumeration as always supported: every
// supported platform ships a standard tool for it (Get-Volume, df).
func (c *Collector) Capability(context.Context, tel.CollectorConfig) (string, tel.CapabilityState) {
	return "", tel.CapSupported
}

// Collect gathers mounted volume inventory.
func (c *Collector) Collect(ctx context.Context, _ tel.CollectorConfig) (any, tel.CollectorResult) {
	res, done := tel.NewResult(c.Name(), c.Section())

	sig := platformVolumes(ctx)
	for _, w := range sig.Warnings {
		res.AddWarning(w)
	}

	sortVolumes(sig.Volumes)

	return Payload{Volumes: sig.Volumes}, *done(sig.Err, sig.Source, len(sig.Volumes))
}

// sortVolumes orders the list deterministically by mount point (falling back
// to drive letter, for Windows entries that share a mount point concept
// differently), so an unchanged volume set hashes identically cycle to
// cycle — Fingerprint's documented requirement for any list payload.
func sortVolumes(v []Volume) {
	sort.Slice(v, func(i, j int) bool {
		if v[i].MountPoint != v[j].MountPoint {
			return v[i].MountPoint < v[j].MountPoint
		}
		return v[i].DriveLetter < v[j].DriveLetter
	})
}
