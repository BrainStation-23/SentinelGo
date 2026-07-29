package epm

import "time"

// ContextSnapshot is the device/user/network state a rule may condition on.
// Every field is a discrete, cheap-to-compare value — nothing here is
// collected on the request path. The collector that populates a snapshot
// (internal/epm/devicectx, Phase 4) imports this package; this package never
// imports it back, so the engine's dependency footprint stays tiny and its
// tests stay fast regardless of what collection eventually costs.
//
// The zero value (no ContextProvider wired, i.e. epm_context_mode=off) has an
// empty Sources map, which makes every context-sourced Matcher report
// known=false — see matchers_context.go. That is what makes "no context
// provider configured" behave identically to today's agent: every context
// condition is Unknown, and an allow-family rule that carries one simply
// never matches, so existing rules (which use none) are unaffected.
type ContextSnapshot struct {
	CollectedAt time.Time

	// Device / posture.
	Hostname, OSType, OSVersion string
	DomainJoined                Tri
	DomainName                  string
	EntraJoined                 Tri
	TenantID                    string
	DiskEncryption              string // "encrypted"|"unencrypted"|"partial"|"unknown"
	SecureBoot                  string // "enabled"|"disabled"|"unsupported"|"unknown"
	FirewallState               string // "enabled"|"partial"|"disabled"|"unknown"
	AntivirusHealth             string // "healthy"|"unhealthy"|"none"|"unknown"
	Compliance                  string // posture summary
	TPMStatus                   string

	// Org — sourced from the active policy bundle's Defaults (Phase 3), not
	// from the OS.
	DeviceGroups []string
	Org          string
	Department   string

	// Network.
	NetworkType      string // "wired"|"wifi"|"cellular"|"unknown"
	VPNActive        Tri
	CorporateNetwork Tri
	DNSSuffixes      []string
	Gateways         []string
	SSID             string

	// Sources tracks, per logical source ("posture", "network", "join", …),
	// when it last collected successfully — the basis for MaxAge staleness
	// checks in matchers_context.go. A key absent from this map means that
	// source has never run.
	Sources map[string]SourceState
}

// SourceState is the freshness and health of one ContextSnapshot source.
type SourceState struct {
	CollectedAt time.Time
	OK          bool
	Err         string
}

// ContextProvider supplies a snapshot cheaply enough to call on every
// elevation request. Implementations MUST NOT block or perform I/O in
// Snapshot — the real implementation (Phase 4) is a single atomic pointer
// load plus a struct copy, with all actual collection happening in a
// background goroutine on its own cadence.
//
// Engine's zero value has a nil ContextProvider (see engine_v2.go), which
// EvaluateV2 checks directly rather than defaulting to a no-op
// implementation of this interface — one nil check is simpler than a type
// that exists solely to be indistinguishable from absence. The effect is the
// same either way: every context-sourced condition reports Unknown, so the
// engine is correct out of the box, before Phase 4 exists at all.
type ContextProvider interface {
	Snapshot() ContextSnapshot
}

// TimeDefaults carries the tenant-wide time-of-day settings CondBusinessHours
// and CondDayOfWeek consult. It is a deliberately small, forward-compatible
// subset of the full policy-bundle Defaults type Phase 3 introduces — the
// engine only needs the time fields to evaluate those two condition kinds
// today; Phase 3 adds the rest (corporate-network definitions, device groups,
// org/department) without touching this type or the engine's dependency on
// it.
type TimeDefaults struct {
	// BusinessHoursStart/End are "HH:MM" in 24-hour form. Both empty means no
	// business-hours policy is configured, in which case CondBusinessHours
	// simply does not match (not Unknown — "no policy configured" is itself a
	// known fact).
	BusinessHoursStart string
	BusinessHoursEnd   string
	// BusinessDays is a subset of {"Mon","Tue","Wed","Thu","Fri","Sat","Sun"}.
	// Empty means every day.
	BusinessDays []string
	// Timezone is the IANA zone business hours are evaluated in. Empty means
	// the device's local zone.
	Timezone string
}
