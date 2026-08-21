// Package encryption implements the telemetry Encryption Detail collector,
// filling the "encryption" section with per-volume disk encryption state:
// BitLocker on Windows, FileVault on macOS, LUKS on Linux.
//
// This is additive to, and does not replace, whatever coarse encryption
// signal the legacy inventory pipeline already reports — see
// docs/telemetry/06-existing-code-observations.md's note that some overlap
// between the legacy payload and new sections is an accepted transitional
// cost. This section is the authoritative, detailed source going forward:
// per-volume protection status, encryption percentage, and (on Windows) key
// protector types.
package encryption

import (
	"context"
	"sort"

	tel "sentinelgo/internal/telemetry"
)

// Name is the collector's identifier, also used as its section name.
const Name = tel.SectionEncryption

// Volume describes one volume's encryption state.
type Volume struct {
	MountPoint  string `json:"mount_point,omitempty"`
	DriveLetter string `json:"drive_letter,omitempty"`
	// EncryptionType is "bitlocker", "filevault", "luks", or "none".
	EncryptionType string `json:"encryption_type,omitempty"`
	// ProtectionStatus is "on", "off", or "unknown" — the platform's own
	// state, not inferred.
	ProtectionStatus string `json:"protection_status,omitempty"`
	// EncryptionPercentage is Windows-only (BitLocker reports it during an
	// in-progress encrypt/decrypt); nil elsewhere or when not mid-operation.
	EncryptionPercentage *float64 `json:"encryption_percentage,omitempty"`
	// KeyProtectorTypes is Windows-only: "Tpm", "RecoveryPassword",
	// "Password", "ExternalKey", etc. — how the volume's key is protected.
	KeyProtectorTypes []string `json:"key_protector_types,omitempty"`
}

// Payload is the wire shape of the "encryption" section.
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

// Collector implements telemetry.Collector for per-volume encryption state.
type Collector struct{}

// New returns the Encryption Detail collector.
func New() *Collector { return &Collector{} }

func (c *Collector) Name() string       { return Name }
func (c *Collector) Section() string    { return tel.SectionEncryption }
func (c *Collector) SchemaVersion() int { return 1 }

// Capability reports storage.encryption as supported whenever this platform
// has a mechanism to ask at all (BitLocker cmdlets, fdesetup, lsblk are all
// part of a standard OS install), never gated on whether any volume actually
// turns out to be encrypted — an all-unencrypted fleet is a real, reportable
// answer, not an absent capability.
func (c *Collector) Capability(ctx context.Context, _ tel.CollectorConfig) (string, tel.CapabilityState) {
	return tel.CapKeyStorageEncryption, platformCapability(ctx)
}

// Collect gathers per-volume encryption state.
func (c *Collector) Collect(ctx context.Context, _ tel.CollectorConfig) (any, tel.CollectorResult) {
	res, done := tel.NewResult(c.Name(), c.Section())

	sig := platformVolumes(ctx)
	for _, w := range sig.Warnings {
		res.AddWarning(w)
	}

	sortVolumes(sig.Volumes)

	return Payload{Volumes: sig.Volumes}, *done(sig.Err, sig.Source, len(sig.Volumes))
}

// sortVolumes orders the list deterministically, so an unchanged volume set
// hashes identically cycle to cycle — Fingerprint's documented requirement
// for any list payload.
func sortVolumes(v []Volume) {
	sort.Slice(v, func(i, j int) bool {
		if v[i].MountPoint != v[j].MountPoint {
			return v[i].MountPoint < v[j].MountPoint
		}
		return v[i].DriveLetter < v[j].DriveLetter
	})
}
