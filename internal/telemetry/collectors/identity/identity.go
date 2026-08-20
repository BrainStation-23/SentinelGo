// Package identity implements the telemetry Device Identity collector.
//
// It fills the "identity" section: hostname, FQDN, hardware manufacturer and
// model, serial number, asset tag, device UUID, machine ID and board serial.
// Per docs/telemetry/03-collection-matrix.md, most of these fields already
// have a proven cross-platform implementation in internal/osinfo/system — this
// collector reuses that code read-only (per docs/telemetry/04-architecture.md's
// governing constraint) and adds only what is missing: manufacturer, asset
// tag, device UUID, machine ID and board serial.
package identity

import (
	"context"
	"os"

	"sentinelgo/internal/osinfo/system"
	tel "sentinelgo/internal/telemetry"
)

// Name is the collector's identifier, also used as its section name.
const Name = tel.SectionIdentity

// Payload is the wire shape of the "identity" section.
type Payload struct {
	Hostname     string `json:"hostname"`
	FQDN         string `json:"fqdn,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	AssetTag     string `json:"asset_tag,omitempty"`
	DeviceUUID   string `json:"device_uuid,omitempty"`
	MachineID    string `json:"machine_id,omitempty"`
	BoardSerial  string `json:"board_serial,omitempty"`
	ChassisType  string `json:"chassis_type,omitempty"`
}

// extra holds the fields platform code must supply that internal/osinfo/system
// does not already expose.
type extra struct {
	Manufacturer string
	AssetTag     string
	DeviceUUID   string
	MachineID    string
	BoardSerial  string
	// Source names the mechanism used to gather extra, e.g.
	// "wmi:root/cimv2:Win32_ComputerSystem".
	Source   string
	Warnings []string
}

// platformExtra is implemented per-OS in identity_<os>.go.

// Collector implements telemetry.Collector for device identity.
type Collector struct{}

// New returns the Device Identity collector.
func New() *Collector { return &Collector{} }

func (c *Collector) Name() string       { return Name }
func (c *Collector) Section() string    { return tel.SectionIdentity }
func (c *Collector) SchemaVersion() int { return 1 }

// Capability reports device identity as always supported. Every device this
// agent runs on has a hostname; there is no meaningful "not present" or
// "unsupported" state for this section, so — like the cpu and os sections —
// it does not own a capability manifest key.
func (c *Collector) Capability(context.Context, tel.CollectorConfig) (string, tel.CapabilityState) {
	return "", tel.CapSupported
}

// Collect gathers device identity fields. Individual field failures degrade
// gracefully to an empty string rather than failing the whole collection: a
// missing asset tag is normal on most hardware, not an error.
func (c *Collector) Collect(ctx context.Context, _ tel.CollectorConfig) (any, tel.CollectorResult) {
	res, done := tel.NewResult(c.Name(), c.Section())

	hostname, _ := os.Hostname()
	ex := platformExtra(ctx)

	payload := Payload{
		Hostname:     hostname,
		FQDN:         system.GetFQDN(),
		Manufacturer: ex.Manufacturer,
		Model:        system.GetHardwareModel(),
		SerialNumber: system.GetSerialNumber(),
		AssetTag:     ex.AssetTag,
		DeviceUUID:   ex.DeviceUUID,
		MachineID:    ex.MachineID,
		BoardSerial:  ex.BoardSerial,
		ChassisType:  system.GetChassisType(),
	}

	for _, w := range ex.Warnings {
		res.AddWarning(w)
	}

	return payload, *done(nil, ex.Source, 1)
}
