// Package directory implements the telemetry AD/Entra/Domain Join collector,
// filling the "directory" section: on-prem Active Directory join state,
// Entra ID (Azure AD) join state, and the tenant/device identifiers that go
// with an Entra join.
package directory

import (
	"context"

	tel "sentinelgo/internal/telemetry"
)

// Name is the collector's identifier, also used as its section name.
const Name = tel.SectionDirectory

// Payload is the wire shape of the "directory" section.
//
// DomainJoined and EntraJoined are *bool, not bool: a lookup that failed to
// run must not collapse to "false", which a consumer cannot distinguish from
// a confirmed negative answer. nil (omitted from the wire) means "could not be
// determined this cycle"; a non-nil pointer, even &false, means the platform
// mechanism ran and produced a trustworthy answer either way.
type Payload struct {
	DomainJoined *bool  `json:"domain_joined,omitempty"`
	Domain       string `json:"domain,omitempty"`
	// EntraJoined, TenantID and DeviceID are Windows-only (dsregcmd);
	// docs/telemetry/03-collection-matrix.md marks Entra ID join as n/a on
	// macOS and Linux, so platform code there never touches them and they stay
	// nil/empty — the same "not applicable" nil a failed lookup would also
	// produce. That's fine: EntraFailed (see signal) is what Collect uses to
	// tell "not applicable on this OS" apart from "attempted and failed", not
	// the payload's own nil-ness.
	EntraJoined *bool  `json:"entra_joined,omitempty"`
	TenantID    string `json:"tenant_id,omitempty"`
	DeviceID    string `json:"device_id,omitempty"`
}

// signal is what platform code supplies before assembling Payload.
type signal struct {
	DomainJoined *bool
	Domain       string
	EntraJoined  *bool
	TenantID     string
	DeviceID     string

	// ADErr is the real, unclassified error from the on-prem AD probe (WMI,
	// realm, sssd or dsconfigad — whichever this platform uses), or nil when it
	// succeeded. Every platform attempts exactly one AD probe, so ADErr != nil
	// always means "attempted and failed", never "not applicable".
	ADErr error
	// EntraErr is the real error from the Entra ID probe (dsregcmd), or nil.
	// Only ever set on Windows: macOS and Linux never attempt this probe at
	// all, so EntraErr stays nil there for a reason indistinguishable from
	// success — which is correct, since "not applicable" must not read as a
	// failure any more than a false lookup result should.
	EntraErr error

	Source   string
	Warnings []string
}

// Collector implements telemetry.Collector for directory join state.
type Collector struct{}

// New returns the AD/Entra/Domain Join collector.
func New() *Collector { return &Collector{} }

func (c *Collector) Name() string       { return Name }
func (c *Collector) Section() string    { return tel.SectionDirectory }
func (c *Collector) SchemaVersion() int { return 1 }

// Capability reports whether this host offers any mechanism to determine
// directory join state at all — see platformCapability. Unlike an earlier
// version of this collector, "no realm and no sssd on this Linux host" is
// CapUnsupported, not a confident CapSupported+false: absence of tooling means
// absence of evidence, not evidence of absence.
func (c *Collector) Capability(ctx context.Context, _ tel.CollectorConfig) (string, tel.CapabilityState) {
	return tel.CapKeyDirectoryJoin, platformCapability(ctx)
}

// Collect gathers directory join state.
//
// Status reflects which probes actually succeeded: if the (universal) AD
// probe failed, its real error drives Status/Error via SanitizeError, so
// "command not found", "permission denied" and "timed out" are reported as
// what they are rather than folded into a generic failure. If AD succeeded but
// the Windows-only Entra probe failed, that downgrades an otherwise-Success
// cycle to StatusPartial — the AD half of the payload is still fully usable,
// which is exactly what Partial means — without letting the AD failure
// classification (were there one) get overwritten by the less severe Entra
// one.
func (c *Collector) Collect(ctx context.Context, _ tel.CollectorConfig) (any, tel.CollectorResult) {
	res, done := tel.NewResult(c.Name(), c.Section())

	sig := platformSignal(ctx)
	for _, w := range sig.Warnings {
		res.AddWarning(w)
	}

	payload := Payload{
		DomainJoined: sig.DomainJoined,
		Domain:       sig.Domain,
		EntraJoined:  sig.EntraJoined,
		TenantID:     sig.TenantID,
		DeviceID:     sig.DeviceID,
	}

	result := done(sig.ADErr, sig.Source, 1)
	applyEntraOutcome(result, sig.ADErr, sig.EntraErr)

	return payload, *result
}

// applyEntraOutcome downgrades an otherwise-successful AD result to
// StatusPartial when the Windows-only Entra probe failed. It never runs when
// the AD probe itself failed: that failure is already the more severe,
// primary-signal problem, driving Status via SanitizeError in Collect, and
// must not be papered over by a "partial" label from the less severe Entra
// failure. Isolated as its own function so this combination rule is unit
// tested without depending on real WMI/dsregcmd/realm calls.
func applyEntraOutcome(result *tel.CollectorResult, adErr, entraErr error) {
	if adErr != nil || entraErr == nil {
		return
	}
	_, reason := tel.SanitizeError(entraErr)
	result.Status = tel.StatusPartial
	result.Error = reason
	result.Sanitize()
}
