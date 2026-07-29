package epm

import (
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// BundleRecord is the persisted-bundle-metadata shape BundleManager reads and
// writes. Declared here — not in internal/store — specifically so both
// BundlePersistence (this file) and *store.EPMStore's implementation of it
// (internal/store/epm_bundle.go, where store.BundleRow is a type alias for
// this) share the exact same type identity. internal/store already imports
// internal/epm (for RuleV2/RuleGroup/PolicyRule), so store referencing an
// epm-declared type creates no cycle; the reverse — epm importing a
// store-declared type — would.
type BundleRecord struct {
	BundleID, ParentID, TenantID, Mode string
	Generation                         int64
	SchemaVersion                      int
	IssuedAt, NotAfter                 time.Time
	KeyID, Signature, SigStatus        string
	Payload                            []byte // the exact bytes that were signed
	ReceivedAt, AppliedAt              time.Time
	State                              string
}

// BundlePersistence is the (optional) persistence seam BundleManager uses to
// survive a restart. Method names and signatures are exactly
// *store.EPMStore's bundle methods (internal/store/epm_bundle.go), so that
// type satisfies this interface structurally with no adapter code. A nil
// BundlePersistence makes BundleManager memory-only: Apply still verifies,
// compiles, canary-checks, and activates a bundle for the life of the
// process — it just cannot answer ActiveBundle after a restart, and
// operator-initiated rollback (native/epm_policy_rollback.go) has nothing to
// roll back to. Acceptable only for tests; every real deployment wires a
// *store.EPMStore in.
type BundlePersistence interface {
	InsertBundle(row BundleRecord) error
	SetBundleState(bundleID, state string) error
	ActivateBundle(bundleID string, appliedAt time.Time) error
	ActiveBundle() (*BundleRecord, error)
	BundleByGeneration(generation int64) (*BundleRecord, error)
	PreviousActiveBundle() (*BundleRecord, error)
	PruneBundles(keep int) error
	UpsertRulesV2(bundleID string, rules []RuleV2) error
	GetRulesV2(bundleID string) ([]RuleV2, error)
	UpsertRuleGroups(bundleID string, groups []RuleGroup) error
	GetRuleGroups(bundleID string) ([]RuleGroup, error)
}

// ApplyResult reports what Apply actually did, for the caller (the
// epm-policy-sync-v2 native task, once Phase 7 exists) to log or report back
// as task status.
type ApplyResult struct {
	BundleID   string
	Generation int64
	SigStatus  SigStatus
	Activated  bool
	// Issues are non-fatal per-rule Compile problems (see CompileIssue) —
	// the bundle still activated with those rules excluded.
	Issues []CompileIssue
	// RejectReason is set (Activated == false) when the bundle was staged
	// but never activated: a hard compile error, a failed canary, or (in
	// "require" signature mode) a bad signature.
	RejectReason string
}

// BundleManager owns the policy bundle lifecycle: verify, stage, compile,
// canary-check, and — only if every one of those passes — activate. It wraps
// an Engine so a successful Apply takes effect immediately via Engine.Swap,
// without stopping the accept loop (see engine_v2.go).
type BundleManager struct {
	engine    *Engine
	matchers  *MatcherRegistry
	store     BundlePersistence // may be nil — see BundlePersistence's doc comment
	sigMode   string
	now       func() time.Time
	keepCount int // bundle retention — PruneBundles(keepCount) after each activation

	probationPath string // "" disables the crash-loop guard (see probation.go)
}

// BundleManagerOption configures a BundleManager.
type BundleManagerOption func(*BundleManager)

func WithBundleStore(s BundlePersistence) BundleManagerOption {
	return func(m *BundleManager) { m.store = s }
}
func WithSignatureMode(mode string) BundleManagerOption {
	return func(m *BundleManager) { m.sigMode = mode }
}
func WithBundleClock(now func() time.Time) BundleManagerOption {
	return func(m *BundleManager) { m.now = now }
}
func WithBundleRetention(keep int) BundleManagerOption {
	return func(m *BundleManager) { m.keepCount = keep }
}
func WithProbationPath(path string) BundleManagerOption {
	return func(m *BundleManager) { m.probationPath = path }
}

// NewBundleManager builds a BundleManager over engine — Apply calls
// engine.Swap on success, so engine should be the same *Engine the platform
// Server/PipeServer/SocketServer was constructed with (WithEngine, see
// server.go) for activation to take effect on the live enforcement path.
func NewBundleManager(engine *Engine, opts ...BundleManagerOption) *BundleManager {
	m := &BundleManager{
		engine: engine, matchers: DefaultMatchers(),
		sigMode: SignatureModeWarn, now: time.Now, keepCount: 3,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Apply verifies sb's signature, decodes and compiles its PolicyBundle, runs
// its canary suite against the newly-compiled rule set, and — only if every
// step passes — activates it (persists as active, swaps the live Engine).
// Any failure along the way leaves whatever bundle was previously active
// untouched and in force: a default-deny system that accepts a broken bundle
// locks every user out of every elevation, so this gate is not optional.
func (m *BundleManager) Apply(sb *SignedBundle) (ApplyResult, error) {
	now := m.now()

	sigStatus, sigErr := VerifyBundle(sb, m.sigMode)
	if sigErr != nil {
		return ApplyResult{SigStatus: sigStatus, RejectReason: sigErr.Error()}, sigErr
	}

	bundle, err := sb.DecodePayload()
	if err != nil {
		return ApplyResult{SigStatus: sigStatus, RejectReason: "malformed payload"}, fmt.Errorf("decode bundle payload: %w", err)
	}

	if bundle.Mode == "delta" {
		merged, err := m.resolveDelta(bundle)
		if err != nil {
			return ApplyResult{BundleID: bundle.BundleID, Generation: bundle.Generation, SigStatus: sigStatus,
				RejectReason: err.Error()}, err
		}
		bundle = merged
	}

	if m.store != nil {
		if err := m.store.InsertBundle(BundleRecord{
			BundleID: bundle.BundleID, Generation: bundle.Generation, ParentID: bundle.ParentID,
			TenantID: bundle.TenantID, Mode: bundle.Mode, SchemaVersion: bundle.SchemaVersion,
			IssuedAt: bundle.IssuedAt, NotAfter: bundle.NotAfter,
			KeyID: sb.KeyID, Signature: sb.Signature, SigStatus: string(sigStatus),
			Payload: sb.Payload, ReceivedAt: now, State: "staged",
		}); err != nil {
			return ApplyResult{BundleID: bundle.BundleID, SigStatus: sigStatus}, fmt.Errorf("stage bundle: %w", err)
		}
	}

	set, issues, err := Compile(bundle.Rules, bundle.RuleGroups, m.matchers)
	if err != nil {
		m.reject(bundle.BundleID, "compile: "+err.Error())
		return ApplyResult{BundleID: bundle.BundleID, Generation: bundle.Generation, SigStatus: sigStatus,
			Issues: issues, RejectReason: "compile: " + err.Error()}, err
	}
	set.BundleID = bundle.BundleID
	set.Generation = bundle.Generation
	set.Defaults = bundle.Defaults.TimeDefaults

	// A bundle that authored at least one rule but ended up compiling to
	// none at all (every rule individually failed — see CompileIssue) is
	// rejected outright, the same fail-safe already applied to v1's
	// "malformed payload silently wipes the policy cache" bug
	// (native/epm_policy_sync.go's errNoRulesKey). Compile() itself
	// correctly treats a per-rule failure as non-fatal to the REST of the
	// bundle, but activating a policy that ended up with nothing in it,
	// under default-deny, would lock every user out of every elevation —
	// exactly the outcome a signature/canary/compile gate exists to prevent.
	// An intentionally empty bundle (len(bundle.Rules) == 0) is unaffected:
	// that is the legitimate "clear all policy" instruction.
	if len(bundle.Rules) > 0 && len(set.rules) == 0 {
		reason := fmt.Sprintf("all %d authored rules failed to compile, leaving no usable policy", len(bundle.Rules))
		m.reject(bundle.BundleID, reason)
		return ApplyResult{BundleID: bundle.BundleID, Generation: bundle.Generation, SigStatus: sigStatus,
			Issues: issues, RejectReason: reason}, fmt.Errorf("%s", reason)
	}

	if failed := runCanaries(set, bundle.Defaults.Canaries, m.matchers, now); failed != "" {
		m.reject(bundle.BundleID, failed)
		return ApplyResult{BundleID: bundle.BundleID, Generation: bundle.Generation, SigStatus: sigStatus,
			Issues: issues, RejectReason: failed}, fmt.Errorf("canary check failed: %s", failed)
	}

	if m.store != nil {
		if err := m.store.UpsertRulesV2(bundle.BundleID, bundle.Rules); err != nil {
			return ApplyResult{BundleID: bundle.BundleID, SigStatus: sigStatus}, fmt.Errorf("save rules: %w", err)
		}
		if err := m.store.UpsertRuleGroups(bundle.BundleID, bundle.RuleGroups); err != nil {
			return ApplyResult{BundleID: bundle.BundleID, SigStatus: sigStatus}, fmt.Errorf("save rule groups: %w", err)
		}
		if err := m.store.ActivateBundle(bundle.BundleID, now); err != nil {
			return ApplyResult{BundleID: bundle.BundleID, SigStatus: sigStatus}, fmt.Errorf("activate bundle: %w", err)
		}
		if err := m.store.PruneBundles(m.keepCount); err != nil {
			log.Printf("epm: prune old bundles: %v", err)
		}
	}

	m.engine.Swap(set)
	m.recordProbation(bundle.BundleID)

	return ApplyResult{
		BundleID: bundle.BundleID, Generation: bundle.Generation,
		SigStatus: sigStatus, Activated: true, Issues: issues,
	}, nil
}

func (m *BundleManager) reject(bundleID, reason string) {
	log.Printf("epm: bundle %q rejected: %s", bundleID, reason)
	if m.store != nil {
		if err := m.store.SetBundleState(bundleID, "rejected"); err != nil {
			log.Printf("epm: mark bundle %q rejected: %v", bundleID, err)
		}
	}
}

// resolveDelta turns a delta bundle into a full one by applying it on top of
// the currently active bundle — see ApplyDelta.
func (m *BundleManager) resolveDelta(delta *PolicyBundle) (*PolicyBundle, error) {
	if m.store == nil {
		return nil, fmt.Errorf("delta bundle received but no persistence is configured to resolve it against")
	}
	active, err := m.store.ActiveBundle()
	if err != nil {
		return nil, fmt.Errorf("load active bundle: %w", err)
	}
	if active == nil {
		return nil, fmt.Errorf("delta bundle received but no bundle is currently active to apply it to")
	}
	var base PolicyBundle
	if err := json.Unmarshal(active.Payload, &base); err != nil {
		return nil, fmt.Errorf("decode active bundle: %w", err)
	}
	return ApplyDelta(&base, delta)
}

// ApplyDelta produces a new full bundle from base + delta. A delta whose
// ParentID does not match base's BundleID is rejected outright — deltas
// never apply out of order, so a client that has fallen behind (or a
// backend that generated the delta against a bundle the agent never saw)
// must fall back to requesting a full bundle instead.
func ApplyDelta(base, delta *PolicyBundle) (*PolicyBundle, error) {
	if delta.Mode != "delta" {
		return nil, fmt.Errorf("ApplyDelta: delta.Mode = %q, want \"delta\"", delta.Mode)
	}
	if delta.ParentID != base.BundleID {
		return nil, fmt.Errorf("delta's parent %q does not match the active bundle %q; a full bundle is required",
			delta.ParentID, base.BundleID)
	}

	merged := *base
	merged.BundleID = delta.BundleID
	merged.Generation = delta.Generation
	merged.ParentID = delta.ParentID
	merged.Mode = "full"
	merged.IssuedAt = delta.IssuedAt
	merged.NotAfter = delta.NotAfter
	if delta.TenantID != "" {
		merged.TenantID = delta.TenantID
	}

	removed := make(map[string]bool, len(delta.RemovedIDs))
	for _, id := range delta.RemovedIDs {
		removed[id] = true
	}
	byID := make(map[string]RuleV2, len(base.Rules))
	var order []string
	for _, r := range base.Rules {
		if !removed[r.ID] {
			if _, exists := byID[r.ID]; !exists {
				order = append(order, r.ID)
			}
			byID[r.ID] = r
		}
	}
	for _, r := range delta.Rules {
		if _, exists := byID[r.ID]; !exists {
			order = append(order, r.ID)
		}
		byID[r.ID] = r
	}
	merged.Rules = make([]RuleV2, 0, len(order))
	for _, id := range order {
		merged.Rules = append(merged.Rules, byID[id])
	}

	groupsByID := make(map[string]RuleGroup, len(base.RuleGroups))
	var groupOrder []string
	for _, g := range base.RuleGroups {
		if _, exists := groupsByID[g.ID]; !exists {
			groupOrder = append(groupOrder, g.ID)
		}
		groupsByID[g.ID] = g
	}
	for _, g := range delta.RuleGroups {
		if _, exists := groupsByID[g.ID]; !exists {
			groupOrder = append(groupOrder, g.ID)
		}
		groupsByID[g.ID] = g
	}
	merged.RuleGroups = make([]RuleGroup, 0, len(groupOrder))
	for _, id := range groupOrder {
		merged.RuleGroups = append(merged.RuleGroups, groupsByID[id])
	}

	// Defaults is not itemized/diffed the way Rules/RuleGroups are: a delta
	// bundle that includes a Defaults block is assumed to carry the complete,
	// current value (the backend already tracks full tenant state), so it
	// replaces the base's wholesale rather than being merged field by field.
	// defaultsIsZero guards against a delta.Defaults containing a slice
	// field (BusinessDays etc.), which makes Defaults non-comparable with ==.
	if !defaultsIsZero(delta.Defaults) {
		merged.Defaults = delta.Defaults
	}
	return &merged, nil
}

// defaultsIsZero reports whether d has no fields set at all. Defaults embeds
// TimeDefaults, which carries a []string (BusinessDays), so d == (Defaults{})
// does not compile — this is the field-by-field check that stands in.
func defaultsIsZero(d Defaults) bool {
	return d.BusinessHoursStart == "" && d.BusinessHoursEnd == "" && d.Timezone == "" &&
		len(d.BusinessDays) == 0 && d.DefaultVerdict == "" &&
		len(d.CorporateDNSSuffixes) == 0 && len(d.CorporateCIDRs) == 0 &&
		len(d.CorporateGatewayMACs) == 0 && len(d.VPNAdapterPatterns) == 0 &&
		len(d.DeviceGroups) == 0 && d.Org == "" && d.Department == "" && len(d.Canaries) == 0
}

// runCanaries evaluates every canary in canaries against set and returns a
// non-empty failure description on the first mismatch, or "" if all passed
// (including the trivially-true case of zero canaries — a bundle with no
// canaries is not thereby invalid, it just has no compile-time self-check).
// Evaluated at "now" (not a canary-supplied timestamp — ElevationRequestV2
// carries no time field of its own; EvalInput.Now is always caller-supplied)
// so a canary that depends on CondBusinessHours/CondDayOfWeek checks against
// the moment the bundle is actually being applied.
func runCanaries(set *CompiledRuleSet, canaries []Canary, matchers *MatcherRegistry, now time.Time) string {
	if len(canaries) == 0 {
		return ""
	}
	tmpEngine := NewEngineWithSet(set, WithMatcherRegistry(matchers))
	for _, c := range canaries {
		d := tmpEngine.EvaluateV2(EvalInput{Now: now, Request: c.Request, Context: c.Context})
		if d.Outcome.Verdict != c.Expected {
			return fmt.Sprintf("canary %q: got verdict %s, want %s", c.Name, d.Outcome.Verdict, c.Expected)
		}
	}
	return ""
}

// recordProbation resets the crash-loop guard's state file (see
// probation.go) to a fresh window for the just-activated bundle: a
// deliberate policy change is not itself a "boot" and must not inherit
// whatever boot count the previous bundle had accumulated. The boot-count
// increment that actually detects a crash loop happens once per process
// startup, via RecordBundleBoot — called separately, from agent startup
// wiring, before any new Apply — not here. Best effort: a failure to write
// degrades to "no automatic rollback protection for this activation", not a
// failed Apply.
func (m *BundleManager) recordProbation(bundleID string) {
	if m.probationPath == "" {
		return
	}
	state := &probationState{BundleID: bundleID, ActivatedAt: m.now(), BootCount: 1}
	if err := saveProbationState(m.probationPath, state); err != nil {
		log.Printf("epm: record probation state: %v", err)
	}
}
