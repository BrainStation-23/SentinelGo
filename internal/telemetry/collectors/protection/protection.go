// Package protection implements the telemetry Endpoint Protection collector,
// filling the "security_protection" section with the controls whose loss leaves
// a device exposed immediately: host firewall state, anti-malware real-time
// protection, and tamper protection.
//
// It is deliberately a separate collector and section from "security_posture"
// (password policy, privileged accounts). One collector reports one status and
// one capability key, so merging them would report the weaker of the two
// outcomes for both: a host whose firewall query fails would look as though its
// password policy were unreadable too.
//
// This section is what makes the firewall_disabled, realtime_protection_disabled
// and tamper_protection_disabled change events possible. Everything reported
// here is read from the same platform mechanisms the shipping
// internal/osinfo/security collectors already use (netsh and Get-MpComputerStatus
// on Windows, ufw/firewalld/iptables on Linux, socketfilterfw on macOS), so no
// new or unproven detection is being introduced — but the queries are narrowed
// to just these controls and made context-aware, which the osinfo helpers are
// not.
package protection

import (
	"context"
	"sort"

	tel "sentinelgo/internal/telemetry"
)

// Name is the collector's identifier, also used as its section name.
const Name = tel.SectionProtection

// Control states.
//
// StateUnknown is a first-class answer and never means "off". The whole value
// of this section is that it feeds security alerting, and a query that failed
// must not be able to page someone at 3am claiming the firewall was turned off.
const (
	StateEnabled  = "enabled"
	StateDisabled = "disabled"
	StatePartial  = "partial"
	StateUnknown  = "unknown"
)

// Profile is one firewall zone or policy profile.
type Profile struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// Firewall is the host firewall's aggregate state plus its per-profile detail.
//
// State is "partial" when some profiles are on and others are off — a real and
// common Windows configuration that neither "enabled" nor "disabled" describes
// honestly.
type Firewall struct {
	State    string    `json:"state"`
	Profiles []Profile `json:"profiles,omitempty"`
	// Mechanism names what was queried, e.g. "exec:netsh".
	Mechanism string `json:"mechanism,omitempty"`
}

// Control is one boolean protection feature.
type Control struct {
	State string `json:"state"`
	// Product names the software the state was read from, where the platform
	// reports it (e.g. "Microsoft Defender").
	Product string `json:"product,omitempty"`
}

// Payload is the wire shape of the "security_protection" section.
type Payload struct {
	Firewall           Firewall `json:"firewall"`
	RealtimeProtection Control  `json:"realtime_protection"`
	TamperProtection   Control  `json:"tamper_protection"`
}

// signal is what platform code supplies before assembling Payload.
type signal struct {
	Payload  Payload
	Err      error
	Source   string
	Warnings []string
}

// Collector implements telemetry.Collector for endpoint protection controls.
type Collector struct{}

// New returns the Endpoint Protection collector.
func New() *Collector { return &Collector{} }

func (c *Collector) Name() string       { return Name }
func (c *Collector) Section() string    { return tel.SectionProtection }
func (c *Collector) SchemaVersion() int { return 1 }

// Capability reports the firewall as the section's gating key: every supported
// platform ships a host firewall with a queryable state, so this is
// CapSupported everywhere and never gates the section off.
//
// Real-time and tamper protection are reported through SubCapabilities instead,
// because they are genuinely absent on some platforms and returning a
// non-supported state here would suppress the firewall reading along with them.
func (c *Collector) Capability(context.Context, tel.CollectorConfig) (string, tel.CapabilityState) {
	return tel.CapKeyFirewall, tel.CapSupported
}

// SubCapabilities reports the two controls that do not exist everywhere.
//
// The states are platform constants rather than probe results on purpose: what
// they answer is "can this operating system report the control at all", which
// does not vary between two machines running the same OS, and probing for it
// would cost a second query per cycle to learn something already known at
// compile time. Whether the control is on at a given moment is the payload's
// job, not the capability's.
func (c *Collector) SubCapabilities(context.Context, tel.CollectorConfig) map[string]tel.CapabilityState {
	return map[string]tel.CapabilityState{
		tel.CapKeyRealtimeProtection: realtimeProtectionCapability,
		tel.CapKeyTamperProtection:   tamperProtectionCapability,
	}
}

// Collect reads the current protection state.
func (c *Collector) Collect(ctx context.Context, _ tel.CollectorConfig) (any, tel.CollectorResult) {
	res, done := tel.NewResult(c.Name(), c.Section())

	sig := platformProtection(ctx)
	for _, w := range sig.Warnings {
		res.AddWarning(w)
	}

	payload := sig.Payload
	sortProfiles(payload.Firewall.Profiles)
	normalize(&payload)

	return payload, *done(sig.Err, sig.Source, 1)
}

// sortProfiles orders profiles deterministically so an unchanged firewall
// configuration hashes identically cycle to cycle — Fingerprint's documented
// requirement for any list payload.
func sortProfiles(p []Profile) {
	sort.Slice(p, func(i, j int) bool { return p[i].Name < p[j].Name })
}

// normalize coerces anything unrecognised to "unknown", so a platform typo
// cannot reach the wire as a state a consumer would raise an alert on.
func normalize(p *Payload) {
	p.Firewall.State = normalizeFirewallState(p.Firewall.State)
	p.RealtimeProtection.State = normalizeControlState(p.RealtimeProtection.State)
	p.TamperProtection.State = normalizeControlState(p.TamperProtection.State)
}

func normalizeFirewallState(s string) string {
	switch s {
	case StateEnabled, StateDisabled, StatePartial:
		return s
	default:
		return StateUnknown
	}
}

func normalizeControlState(s string) string {
	switch s {
	case StateEnabled, StateDisabled:
		return s
	default:
		return StateUnknown
	}
}

// firewallStateFrom aggregates per-profile states.
//
// An empty profile list is "unknown", not "disabled": it means the query
// returned nothing, and treating that as a disabled firewall would raise a
// false critical alert on every host whose firewall tool is missing.
func firewallStateFrom(profiles []Profile) string {
	if len(profiles) == 0 {
		return StateUnknown
	}
	var on, off int
	for _, p := range profiles {
		if p.Enabled {
			on++
		} else {
			off++
		}
	}
	switch {
	case off == 0:
		return StateEnabled
	case on == 0:
		return StateDisabled
	default:
		return StatePartial
	}
}
