// Package posture implements the telemetry Security Posture collector,
// filling the "security_posture" section with machine-wide password policy
// and the accounts holding administrative privilege.
//
// Screen-lock state is deliberately not collected here. It is inherently
// per-interactive-user (a screen saver timeout lives in the logged-in user's
// own profile — HKCU on Windows, ~/Library on macOS, dconf/gsettings on
// Linux), and this agent runs as a system service (SYSTEM/root), whose own
// profile is not the interactive user's. Reading it correctly needs the
// HKEY_USERS-per-SID idiom docs/telemetry/03-collection-matrix.md points to
// (already proven in internal/service/software/collect_windows.go) extended
// to two more platforms' equivalents — real work, deferred rather than
// rushed into this pass, where reporting the SYSTEM account's own (always
// empty/irrelevant) screen-lock setting would be actively misleading, worse
// than reporting nothing.
//
// Password policy is machine- or domain-wide (net accounts, login.defs, PAM),
// and privileged-account membership is a machine-local group, so neither has
// this blind spot.
package posture

import (
	"context"
	"sort"

	tel "sentinelgo/internal/telemetry"
)

// Name is the collector's identifier, also used as its section name.
const Name = tel.SectionSecurityPost

// PasswordPolicy is the machine- or domain-wide password policy. Every field
// is a pointer: nil means this platform's mechanism did not report that
// specific value, never a guessed default — a nil MinLength must not be
// confused with a real policy of "no minimum".
type PasswordPolicy struct {
	MinLength              *int `json:"min_length,omitempty"`
	MinAgeDays             *int `json:"min_age_days,omitempty"`
	MaxAgeDays             *int `json:"max_age_days,omitempty"`
	LockoutThreshold       *int `json:"lockout_threshold,omitempty"`
	LockoutDurationMinutes *int `json:"lockout_duration_minutes,omitempty"`
}

// Payload is the wire shape of the "security_posture" section.
type Payload struct {
	PasswordPolicy PasswordPolicy `json:"password_policy"`
	// PrivilegedAccounts lists members of the local administrative group
	// (Administrators on Windows, sudo/wheel on Linux, admin on macOS).
	PrivilegedAccounts []string `json:"privileged_accounts,omitempty"`
}

// signal is what platform code supplies before assembling Payload.
type signal struct {
	Policy             PasswordPolicy
	PrivilegedAccounts []string
	Err                error
	Source             string
	Warnings           []string
}

// Collector implements telemetry.Collector for security posture.
type Collector struct{}

// New returns the Security Posture collector.
func New() *Collector { return &Collector{} }

func (c *Collector) Name() string       { return Name }
func (c *Collector) Section() string    { return tel.SectionSecurityPost }
func (c *Collector) SchemaVersion() int { return 1 }

// Capability reports security posture as always supported: every platform
// has SOME queryable password policy and administrative group, even if a
// specific field within it (see PasswordPolicy's doc comment) cannot always
// be determined.
func (c *Collector) Capability(context.Context, tel.CollectorConfig) (string, tel.CapabilityState) {
	return "", tel.CapSupported
}

// Collect gathers password policy and privileged account membership.
func (c *Collector) Collect(ctx context.Context, _ tel.CollectorConfig) (any, tel.CollectorResult) {
	res, done := tel.NewResult(c.Name(), c.Section())

	sig := platformPosture(ctx)
	for _, w := range sig.Warnings {
		res.AddWarning(w)
	}

	accounts := append([]string(nil), sig.PrivilegedAccounts...)
	sort.Strings(accounts)

	payload := Payload{
		PasswordPolicy:     sig.Policy,
		PrivilegedAccounts: accounts,
	}

	return payload, *done(sig.Err, sig.Source, len(accounts))
}
