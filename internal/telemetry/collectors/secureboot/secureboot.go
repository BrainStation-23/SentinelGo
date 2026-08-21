// Package secureboot implements the telemetry Secure Boot collector, filling
// the "secure_boot" section.
//
// The section was registered from the start but nothing ever filled it, so
// CapKeySecureBoot inherited the capability manifest's default and every
// Windows 11 endpoint reported secure_boot as "unavailable_on_os" — a claim
// about the operating system that nothing had checked, and one that stops an
// operator investigating. This collector makes the answer real.
//
// The per-platform mechanisms mirror the ones already proven in
// internal/osinfo/security (registry on Windows, mokutil/efivars on Linux,
// SPiBridgeDataType on macOS). They are reimplemented here rather than
// imported because telemetry collectors must honour context cancellation and
// the osinfo helpers predate that contract — see the Collector doc comment.
package secureboot

import (
	"context"

	tel "sentinelgo/internal/telemetry"
)

// Name is the collector's identifier, also used as its section name.
const Name = tel.SectionSecureBoot

// Secure Boot states. "unknown" is a first-class answer, not a failure: a
// machine can boot UEFI and still refuse to report the variable, and guessing
// "disabled" there would raise a false security alert on every such device.
const (
	StateEnabled  = "enabled"
	StateDisabled = "disabled"
	StateUnknown  = "unknown"
)

// Payload is the wire shape of the "secure_boot" section.
type Payload struct {
	// State is "enabled", "disabled" or "unknown".
	State string `json:"state"`
	// Enabled is nil when State is "unknown", so a consumer can distinguish
	// "off" from "we could not tell" without string matching.
	Enabled *bool `json:"enabled,omitempty"`
	// Mechanism names what was actually read, e.g. "registry:SecureBoot\State".
	Mechanism string `json:"mechanism,omitempty"`
}

// signal is what platform code supplies before assembling Payload.
type signal struct {
	State     string
	Mechanism string
	Err       error
	Source    string
	Warnings  []string
}

// Collector implements telemetry.Collector for UEFI Secure Boot state.
type Collector struct {
	cache *tel.ProbeCache[tel.CapabilityState]
}

// New returns the Secure Boot collector.
func New() *Collector {
	return &Collector{cache: tel.NewProbeCache[tel.CapabilityState](tel.DefaultProbeTTL)}
}

func (c *Collector) Name() string       { return Name }
func (c *Collector) Section() string    { return tel.SectionSecureBoot }
func (c *Collector) SchemaVersion() int { return 1 }

// Capability distinguishes the three cases that matter operationally: this
// machine has no UEFI firmware to ask (CapNotPresent — a legacy-BIOS or
// CSM-booted host, nothing to fix); the firmware is there and answerable
// (CapSupported); or the platform exposes no mechanism at all (CapUnsupported).
//
// It never returns CapUnavailableOS: all three target operating systems can
// report Secure Boot, so that state would be false on every one of them.
func (c *Collector) Capability(ctx context.Context, _ tel.CollectorConfig) (string, tel.CapabilityState) {
	state := c.cache.Get(func() tel.CapabilityState { return platformCapability(ctx) })
	return tel.CapKeySecureBoot, state
}

// Collect reads the current Secure Boot state.
func (c *Collector) Collect(ctx context.Context, _ tel.CollectorConfig) (any, tel.CollectorResult) {
	res, done := tel.NewResult(c.Name(), c.Section())

	sig := platformSecureBoot(ctx)
	for _, w := range sig.Warnings {
		res.AddWarning(w)
	}

	payload := Payload{State: normalizeState(sig.State), Mechanism: sig.Mechanism}
	if payload.State != StateUnknown {
		enabled := payload.State == StateEnabled
		payload.Enabled = &enabled
	}

	return payload, *done(sig.Err, sig.Source, 1)
}

// normalizeState coerces anything unrecognised to "unknown" rather than
// letting a platform typo reach the wire as a state consumers would act on.
func normalizeState(s string) string {
	switch s {
	case StateEnabled, StateDisabled:
		return s
	default:
		return StateUnknown
	}
}
