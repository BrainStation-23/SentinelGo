// Package osdetail implements the telemetry OS Completeness collector,
// filling the "os" section. It reuses internal/osinfo/system.GetOSInformation
// read-only for the baseline fields already collected (name, version, locale,
// timezone, boot time — see docs/telemetry/04-architecture.md's governing
// constraint) and adds the fields the gap analysis marks missing: install
// date, pending reboot, and Windows activation/licensing status.
//
// End-of-support is deliberately NOT computed here. Doing so would require
// shipping and maintaining a static OS-version-to-EOL-date table inside the
// agent binary — a table that goes stale the moment a new OS version ships
// and that this repository has no mechanism to update independently of a
// full agent release. The section already reports precise name/version/build,
// which is exactly what the backend needs to compute end-of-support from its
// own maintained table instead. Reporting a fabricated or quickly-stale date
// here would be worse than reporting nothing.
package osdetail

import (
	"context"

	"sentinelgo/internal/osinfo/system"
	tel "sentinelgo/internal/telemetry"
)

// Name is the collector's identifier, also used as its section name.
const Name = tel.SectionOS

// Payload is the wire shape of the "os" section.
type Payload struct {
	Name                  string `json:"name"`
	Version               string `json:"version,omitempty"`
	DisplayVersion        string `json:"display_version,omitempty"`
	Type                  string `json:"type,omitempty"`
	Architecture          string `json:"architecture,omitempty"`
	Locale                string `json:"locale,omitempty"`
	Language              string `json:"language,omitempty"`
	TimeZone              string `json:"time_zone,omitempty"`
	TimeZoneOffsetMinutes int    `json:"time_zone_offset_minutes"`
	LastBootTime          string `json:"last_boot_time,omitempty"`
	// InstallDate is best-effort and platform-dependent; empty when no
	// reliable source exists on this host rather than guessed.
	InstallDate string `json:"install_date,omitempty"`
	// PendingReboot is *bool, not bool: a host with no reliable per-cycle
	// mechanism (macOS in this collector's current form — see the package
	// doc) must not report a confident "false" it cannot back up. nil
	// (omitted from the wire) means undetermined; a non-nil pointer means
	// the platform's mechanism actually ran and produced a trustworthy
	// answer either way. This mirrors the fix applied to the directory
	// collector's DomainJoined/EntraJoined fields for the same reason.
	PendingReboot       *bool  `json:"pending_reboot,omitempty"`
	PendingRebootReason string `json:"pending_reboot_reason,omitempty"`
	// ActivationStatus is Windows-only (licensing has no Linux/macOS
	// concept) and stays empty elsewhere.
	ActivationStatus string `json:"activation_status,omitempty"`
}

// extra holds the fields platform code must supply beyond what
// internal/osinfo/system already exposes.
type extra struct {
	InstallDate         string
	PendingReboot       *bool
	PendingRebootReason string
	ActivationStatus    string
	Source              string
	Warnings            []string
}

// Collector implements telemetry.Collector for OS completeness.
type Collector struct{}

// New returns the OS Completeness collector.
func New() *Collector { return &Collector{} }

func (c *Collector) Name() string       { return Name }
func (c *Collector) Section() string    { return tel.SectionOS }
func (c *Collector) SchemaVersion() int { return 1 }

// Capability reports OS information as always supported, the same reasoning
// as the identity collector: every device this agent runs on has a queryable
// OS, and internal/osinfo/system.GetOSInformation already has its own
// fallback chains, so there is no meaningful "not present" or "unsupported"
// state for the section as a whole. Individual best-effort fields (install
// date, pending reboot, activation) degrade to empty/nil on failure instead.
func (c *Collector) Capability(context.Context, tel.CollectorConfig) (string, tel.CapabilityState) {
	return "", tel.CapSupported
}

// Collect gathers OS information.
func (c *Collector) Collect(ctx context.Context, _ tel.CollectorConfig) (any, tel.CollectorResult) {
	res, done := tel.NewResult(c.Name(), c.Section())

	info := system.GetOSInformation()
	ex := platformExtra(ctx)

	for _, w := range ex.Warnings {
		res.AddWarning(w)
	}

	payload := Payload{
		Name:                  info.OSName,
		Version:               info.OSVersion,
		DisplayVersion:        info.OSServicePack,
		Type:                  info.OSType,
		Architecture:          info.Architecture,
		Locale:                info.OSLocale,
		Language:              info.OSLanguage,
		TimeZone:              info.OSTimeZone,
		TimeZoneOffsetMinutes: info.OSTimeZoneOffsetMinutes,
		LastBootTime:          info.OSLastBootTime.DateTime,
		InstallDate:           ex.InstallDate,
		PendingReboot:         ex.PendingReboot,
		PendingRebootReason:   ex.PendingRebootReason,
		ActivationStatus:      ex.ActivationStatus,
	}

	return payload, *done(nil, ex.Source, 1)
}
