// Package tpm implements the telemetry TPM collector, filling the "tpm"
// section with the presence, activation state and spec version of the
// platform's trusted-platform module.
//
// Like secure_boot, the section was registered from the start but nothing
// filled it, so CapKeyTPM inherited the capability manifest's default and every
// Windows endpoint reported "unavailable_on_os" — a claim about the operating
// system that nothing had checked. Windows exposes Win32_Tpm and Linux exposes
// /sys/class/tpm; macOS genuinely has no TPM (the Secure Enclave is different
// hardware with a different trust model, and reporting it as a TPM would be a
// fabricated answer), so darwin is the one platform where CapNotPresent is the
// truthful result.
package tpm

import (
	"context"

	tel "sentinelgo/internal/telemetry"
)

// Name is the collector's identifier, also used as its section name.
const Name = tel.SectionTPM

// Payload is the wire shape of the "tpm" section.
type Payload struct {
	// Present reports whether a TPM device exists at all.
	Present bool `json:"present"`
	// Enabled is nil when presence is known but the activation state is not,
	// so "the TPM is switched off in firmware" stays distinguishable from "we
	// could not read the activation state".
	Enabled *bool `json:"enabled,omitempty"`
	// Version is the spec version, e.g. "2.0" or "1.2". Empty when unknown.
	Version string `json:"version,omitempty"`
	// Manufacturer is reported where the platform exposes it.
	Manufacturer string `json:"manufacturer,omitempty"`
}

// signal is what platform code supplies before assembling Payload.
type signal struct {
	Payload  Payload
	Err      error
	Source   string
	Warnings []string
}

// Collector implements telemetry.Collector for TPM state.
type Collector struct {
	cache *tel.ProbeCache[probe]
}

// probe is one platform interrogation, shared between Capability and Collect so
// the (PowerShell-backed, on Windows) query runs once per cycle rather than
// twice. See telemetry.ProbeCache.
type probe struct {
	capability tel.CapabilityState
	signal     signal
}

// New returns the TPM collector.
func New() *Collector {
	return &Collector{cache: tel.NewProbeCache[probe](tel.DefaultProbeTTL)}
}

func (c *Collector) Name() string       { return Name }
func (c *Collector) Section() string    { return tel.SectionTPM }
func (c *Collector) SchemaVersion() int { return 1 }

// Capability reports whether this endpoint has a TPM the agent can read.
//
// CapNotPresent means no TPM device exists — a desktop or VM without one, or
// any Mac. CapUnsupported means a device is there but its state could not be
// read, which unlike CapNotPresent may be fixable by a driver or firmware
// change. Neither is CapUnavailableOS: Windows and Linux both expose TPM state,
// so that value would be false on both.
func (c *Collector) Capability(ctx context.Context, _ tel.CollectorConfig) (string, tel.CapabilityState) {
	return tel.CapKeyTPM, c.probe(ctx).capability
}

// Collect reports the TPM state gathered by the shared probe.
func (c *Collector) Collect(ctx context.Context, _ tel.CollectorConfig) (any, tel.CollectorResult) {
	res, done := tel.NewResult(c.Name(), c.Section())

	sig := c.probe(ctx).signal
	for _, w := range sig.Warnings {
		res.AddWarning(w)
	}

	return sig.Payload, *done(sig.Err, sig.Source, 1)
}

func (c *Collector) probe(ctx context.Context) probe {
	return c.cache.Get(func() probe { return platformProbe(ctx) })
}
