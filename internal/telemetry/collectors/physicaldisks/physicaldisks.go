// Package physicaldisks implements the telemetry Physical Disks collector,
// filling the "physical_disks" section: one entry per physical storage
// device (model, serial, size, media/bus type, health) plus a best-effort
// SMART summary per disk.
//
// SMART is collected through each platform's own structured decoder
// (PowerShell's Get-StorageReliabilityCounter, smartctl's --json output)
// rather than by hand-decoding the raw ATA attribute table WMI exposes in
// MSStorageDriver_FailurePredictData. docs/telemetry/03-collection-matrix.md
// flags that byte-offset decode as the highest-risk code in the storage
// work, needing its own fixture test to avoid silently-wrong-but-plausible
// numbers; using tools that already parse the structure for us avoids that
// risk class entirely rather than accepting it.
package physicaldisks

import (
	"context"
	"sort"

	tel "sentinelgo/internal/telemetry"
)

// Name is the collector's identifier, also used as its section name.
const Name = tel.SectionPhysicalDisks

// SMART is a best-effort health summary for one disk. Every field is a
// pointer: nil means this platform's mechanism did not report that specific
// value (a common, non-fabricated case — e.g. NVMe wear percentage has no
// ATA-drive equivalent), never a guessed zero.
type SMART struct {
	Healthy            *bool    `json:"healthy,omitempty"`
	TemperatureCelsius *float64 `json:"temperature_celsius,omitempty"`
	PowerOnHours       *uint64  `json:"power_on_hours,omitempty"`
	// WearPercentage is "percentage of rated write endurance consumed" for
	// an SSD/NVMe drive (0 = new, 100 = at rated end of life). Not
	// meaningful for a spinning HDD and left nil there.
	WearPercentage *float64 `json:"wear_percentage,omitempty"`
}

// Disk describes one physical storage device.
type Disk struct {
	ID           string `json:"id"`
	Model        string `json:"model,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	SizeBytes    uint64 `json:"size_bytes"`
	// MediaType is "ssd", "hdd", or "unspecified" when the platform cannot
	// tell (common for USB or virtual disks).
	MediaType string `json:"media_type,omitempty"`
	// BusType is the transport: "nvme", "sata", "usb", "sas", "scsi", etc.
	BusType      string `json:"bus_type,omitempty"`
	HealthStatus string `json:"health_status,omitempty"`
	SMART        *SMART `json:"smart,omitempty"`
}

// Payload is the wire shape of the "physical_disks" section.
type Payload struct {
	Disks []Disk `json:"disks"`
}

// signal is what platform code supplies before assembling Payload.
type signal struct {
	Disks    []Disk
	Err      error
	Source   string
	Warnings []string
}

// Collector implements telemetry.Collector for physical disk inventory.
type Collector struct{}

// New returns the Physical Disks collector.
func New() *Collector { return &Collector{} }

func (c *Collector) Name() string       { return Name }
func (c *Collector) Section() string    { return tel.SectionPhysicalDisks }
func (c *Collector) SchemaVersion() int { return 1 }

// Capability reports disk enumeration as always supported: every supported
// platform ships a standard tool for it (Get-PhysicalDisk, lsblk, diskutil).
// SMART is a best-effort per-disk field, not a section-level capability gate
// — gating the whole section on smartctl's presence, for example, would
// throw away the disk list itself on hosts that simply lack that one tool.
func (c *Collector) Capability(context.Context, tel.CollectorConfig) (string, tel.CapabilityState) {
	return "", tel.CapSupported
}

// SubCapabilities reports whether this host can read SMART at all.
//
// It exists because the manifest and the payload disagreed without it. This
// collector genuinely gathers SMART attributes — temperature, power-on hours,
// wear — but nothing claimed CapKeyStorageSMART, so the key kept the manifest
// default and the backend was told "this build ships no collector for it"
// while the section it belongs to carried the data. An operator reading that
// would conclude SMART was unavailable on a fleet that was reporting it.
//
// It is a SUB-capability rather than this collector's primary one for the
// reason Capability describes: a non-supported state returned from Capability
// makes RunAll skip Collect entirely, so gating on smartctl's presence would
// throw away the disk list itself on a host that merely lacks that one tool.
// This is the same split the processes collector uses for processes.cmdline.
//
// The state describes the MECHANISM, not the result. A disk that reports no
// wear percentage — a spinning HDD, a USB enclosure, a virtual disk — is a nil
// field within a supported capability, not a capability failure.
func (c *Collector) SubCapabilities(ctx context.Context, _ tel.CollectorConfig) map[string]tel.CapabilityState {
	return map[string]tel.CapabilityState{tel.CapKeyStorageSMART: smartCapability(ctx)}
}

// Collect gathers physical disk inventory.
func (c *Collector) Collect(ctx context.Context, _ tel.CollectorConfig) (any, tel.CollectorResult) {
	res, done := tel.NewResult(c.Name(), c.Section())

	sig := platformDisks(ctx)
	for _, w := range sig.Warnings {
		res.AddWarning(w)
	}

	sortDisks(sig.Disks)

	return Payload{Disks: sig.Disks}, *done(sig.Err, sig.Source, len(sig.Disks))
}

// sortDisks orders the list deterministically by ID, so an unchanged disk set
// hashes identically cycle to cycle — Fingerprint's documented requirement
// for any list payload.
func sortDisks(d []Disk) {
	sort.Slice(d, func(i, j int) bool { return d[i].ID < d[j].ID })
}
