package epm

import (
	"fmt"
	"time"
)

// ElevationRequestV2 is the full v2 request shape: everything any Matcher
// might read. It is a strict superset of ElevationRequest — see upgradeRequest
// — and is deliberately wider than what any transport populates today.
// Fields with no current producer (ProductName, MSIProductCode, BundleID,
// PackageName, ParentProcess, ChildProcess, UserGroups) simply stay empty,
// which makes their conditions Unknown (see the corresponding Matcher.Extract
// below) until a later phase's collector populates them — no engine change
// will be needed when that happens.
type ElevationRequestV2 struct {
	RequestID  string
	UserID     string
	UserGroups []string

	AppPath   string
	AppHash   string // lowercase hex SHA-256
	SHA1      string // lowercase hex SHA-1; no current producer (repo hashes SHA-256 only)
	Publisher string // "" is ambiguous between "unsigned" and "verification failed" — see CondSigned's Matcher

	ProductName    string
	MSIProductCode string
	BundleID       string
	PackageName    string

	ScriptPath           string
	ScriptHash           string
	ActualArgs           string
	CommandLine          string
	RequestedServiceName string

	ParentProcess string
	ChildProcess  string
}

// upgradeRequest lowers a v1 ElevationRequest into its v2 superset. Every
// field with no v1 equivalent is left at its zero value, which Extract
// functions read as "unknown" rather than "empty string."
func upgradeRequest(req ElevationRequest) ElevationRequestV2 {
	return ElevationRequestV2{
		RequestID:            req.RequestID,
		UserID:               req.UserID,
		AppPath:              req.AppPath,
		AppHash:              req.AppHash,
		Publisher:            req.Publisher,
		ScriptPath:           req.ScriptPath,
		ScriptHash:           req.ScriptHash,
		ActualArgs:           req.ActualArgs,
		RequestedServiceName: req.RequestedServiceName,
	}
}

// EvalInput is everything the engine may consult for one evaluation. It is
// assembled once per request by the caller (Engine.EvaluateV2); matchers never
// perform I/O and never see anything but this struct.
type EvalInput struct {
	Now     time.Time
	Request ElevationRequestV2
	Context ContextSnapshot
	// Defaults carries the tenant-wide time-of-day settings CondBusinessHours
	// and CondDayOfWeek consult. See TimeDefaults.
	Defaults TimeDefaults
	// Explain requests a populated Decision.Explain trace. Expensive relative
	// to normal evaluation (allocates a slice entry per node visited); never
	// set on the hot request path by default.
	Explain bool
}

// Matcher declares how one ConditionKind projects EvalInput into comparable
// string values. This is the design choice that keeps ~30 condition kinds
// tractable: comparison itself (eq/glob/in/regex/version/between) lives once,
// in applyOperator (compile.go). Adding a new condition kind is a Matcher
// implementation — typically a ~10-line Extract — not a new comparison code
// path.
type Matcher interface {
	Kind() ConditionKind
	// Weight is the base specificity this kind contributes on an exact-operator
	// match; see specificity.go.
	Weight() int
	// MaxAge bounds how stale the underlying fact in EvalInput.Context may be
	// before Extract must report it unknown. Zero means the fact (if present at
	// all) never goes stale — appropriate for anything sourced directly from
	// EvalInput.Request rather than a background-collected ContextSnapshot.
	MaxAge() time.Duration
	// Extract returns the candidate value(s) to compare against a leaf
	// Condition's Value/Values, and whether the fact is known at all. known=false
	// must be returned whenever the fact was never collected, is stale beyond
	// MaxAge, or the platform cannot supply it — never silently substituted
	// with a zero-value string that could be mistaken for a real "" match.
	Extract(in *EvalInput) (values []string, known bool)
}

// MatcherRegistry maps ConditionKind to the Matcher that evaluates it. Unlike
// internal/service/task/native's unsynchronized package-level registry slice,
// this is an explicit value: a test builds exactly the registry it wants
// (e.g. matchers_test.go exercises one kind in isolation), and Compile takes
// one as a parameter rather than reaching for global state.
type MatcherRegistry struct {
	m map[ConditionKind]Matcher
}

// NewMatcherRegistry returns an empty registry.
func NewMatcherRegistry() *MatcherRegistry {
	return &MatcherRegistry{m: make(map[ConditionKind]Matcher)}
}

// Register adds m to the registry. Returns an error if m's Kind is already
// registered — a silent last-writer-wins would be a much harder bug to find
// than a startup-time error.
func (r *MatcherRegistry) Register(m Matcher) error {
	if r.m == nil {
		r.m = make(map[ConditionKind]Matcher)
	}
	if _, exists := r.m[m.Kind()]; exists {
		return fmt.Errorf("matcher registry: kind %q already registered", m.Kind())
	}
	r.m[m.Kind()] = m
	return nil
}

// Lookup returns the Matcher registered for k, if any.
func (r *MatcherRegistry) Lookup(k ConditionKind) (Matcher, bool) {
	if r == nil {
		return nil, false
	}
	m, ok := r.m[k]
	return m, ok
}

// DefaultMatchers returns the full built-in registry — every ConditionKind
// declared in condition.go has an entry. Identity matchers (matchers_identity.go)
// are always meaningfully populated once a transport supplies the
// corresponding request field; context matchers (matchers_context.go) report
// known=false until a ContextProvider is wired (Phase 4) or, for kinds with no
// collector at all yet (product_name, msi_product_code, bundle_id,
// package_name, parent_process, child_process, user_group), until a later
// phase populates the relevant ElevationRequestV2 field.
//
// Panics on a duplicate-registration error, which would be a programming bug
// in this file, not a runtime condition — every call site either wants the
// full built-in set or constructs its own registry directly.
func DefaultMatchers() *MatcherRegistry {
	reg := NewMatcherRegistry()
	for _, m := range allBuiltinMatchers() {
		if err := reg.Register(m); err != nil {
			panic("epm: " + err.Error())
		}
	}
	return reg
}
