package epm

// bundle_manager_test.go is in package epm (not epm_test), so it needs
// unexported access (leaf, probationState, loadProbationState, ...) — which
// rules out importing sentinelgo/internal/store here: an internal test file
// (package epm, not epm_test) is compiled as part of package epm itself for
// import-cycle purposes, and store already imports epm, so store importing
// back would cycle. fakeBundleStore below is a minimal in-memory
// BundlePersistence instead. store.EPMStore's own conformance to
// BundlePersistence is proven separately, at compile time, by
// store/epm_bundle.go's `var _ epm.BundlePersistence = (*EPMStore)(nil)`.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// fakeBundleStore is a minimal in-memory BundlePersistence. It intentionally
// mirrors store.EPMStore's real semantics for the properties tests rely on:
// ActivateBundle supersedes whatever was active (never two bundles active at
// once), InsertBundle upserts by BundleID, and BundleByGeneration/
// ActiveBundle return nil (not an error) when nothing matches.
type fakeBundleStore struct {
	bundles map[string]*BundleRecord
	rules   map[string][]RuleV2
	groups  map[string][]RuleGroup
}

func newFakeBundleStore() *fakeBundleStore {
	return &fakeBundleStore{bundles: map[string]*BundleRecord{}, rules: map[string][]RuleV2{}, groups: map[string][]RuleGroup{}}
}

func (f *fakeBundleStore) InsertBundle(row BundleRecord) error {
	r := row
	f.bundles[row.BundleID] = &r
	return nil
}

func (f *fakeBundleStore) SetBundleState(bundleID, state string) error {
	b, ok := f.bundles[bundleID]
	if !ok {
		return fmt.Errorf("no bundle %q", bundleID)
	}
	b.State = state
	return nil
}

func (f *fakeBundleStore) ActivateBundle(bundleID string, appliedAt time.Time) error {
	target, ok := f.bundles[bundleID]
	if !ok {
		return fmt.Errorf("no bundle %q", bundleID)
	}
	for _, b := range f.bundles {
		if b.State == "active" {
			b.State = "superseded"
		}
	}
	target.State = "active"
	target.AppliedAt = appliedAt
	return nil
}

func (f *fakeBundleStore) ActiveBundle() (*BundleRecord, error) {
	for _, b := range f.bundles {
		if b.State == "active" {
			return b, nil
		}
	}
	return nil, nil
}

func (f *fakeBundleStore) BundleByGeneration(generation int64) (*BundleRecord, error) {
	for _, b := range f.bundles {
		if b.Generation == generation {
			return b, nil
		}
	}
	return nil, nil
}

func (f *fakeBundleStore) PreviousActiveBundle() (*BundleRecord, error) {
	var best *BundleRecord
	for _, b := range f.bundles {
		if b.State == "superseded" && (best == nil || b.Generation > best.Generation) {
			best = b
		}
	}
	return best, nil
}

func (f *fakeBundleStore) PruneBundles(keep int) error { return nil } // no-op: not exercised by these tests

// GetBundle is not part of BundlePersistence — a test-only convenience
// mirroring store.EPMStore.GetBundle, used to assert on a staged bundle's
// state without going through the full interface.
func (f *fakeBundleStore) GetBundle(bundleID string) (*BundleRecord, error) {
	return f.bundles[bundleID], nil
}

func (f *fakeBundleStore) UpsertRulesV2(bundleID string, rules []RuleV2) error {
	f.rules[bundleID] = rules
	return nil
}
func (f *fakeBundleStore) GetRulesV2(bundleID string) ([]RuleV2, error) {
	return f.rules[bundleID], nil
}

func (f *fakeBundleStore) UpsertRuleGroups(bundleID string, groups []RuleGroup) error {
	f.groups[bundleID] = groups
	return nil
}
func (f *fakeBundleStore) GetRuleGroups(bundleID string) ([]RuleGroup, error) {
	return f.groups[bundleID], nil
}

func signedTestBundle(t *testing.T, bundle PolicyBundle) *SignedBundle {
	t.Helper()
	payload, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	return &SignedBundle{Payload: payload}
}

func TestBundleManager_Apply_ActivatesAndSwapsEngine(t *testing.T) {
	engine := NewEngine(nil) // starts with zero rules: default deny
	st := newFakeBundleStore()
	m := NewBundleManager(engine, WithBundleStore(st), WithSignatureMode(SignatureModeOff))

	bundle := PolicyBundle{
		BundleID: "b1", Generation: 1, Mode: "full", IssuedAt: time.Now().UTC(),
		Rules: []RuleV2{{
			ID: "allow-alice", Enabled: true,
			Conditions: leaf(CondUser, OpEquals, "alice"),
			Outcome:    Outcome{Verdict: VerdictAllow},
		}},
	}
	result, err := m.Apply(signedTestBundle(t, bundle))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !result.Activated {
		t.Fatalf("expected Activated=true, got %+v", result)
	}
	if result.BundleID != "b1" || result.Generation != 1 {
		t.Errorf("result = %+v, want BundleID=b1 Generation=1", result)
	}

	// The live engine must reflect the new bundle immediately.
	resp := engine.Evaluate(ElevationRequest{UserID: "alice", Now: time.Now()})
	if !resp.Allowed {
		t.Errorf("engine did not pick up the newly-activated bundle: %+v", resp)
	}

	// And persistence must agree.
	active, err := st.ActiveBundle()
	if err != nil {
		t.Fatalf("ActiveBundle: %v", err)
	}
	if active == nil || active.BundleID != "b1" || active.State != "active" {
		t.Errorf("active bundle in store = %+v, want b1/active", active)
	}
}

func TestBundleManager_Apply_CompileErrorDoesNotSwapEngine(t *testing.T) {
	engine := NewEngine([]PolicyRule{{ID: "v1-rule", AppHash: "abc", Decision: DecisionAllow}})
	st := newFakeBundleStore()
	m := NewBundleManager(engine, WithBundleStore(st), WithSignatureMode(SignatureModeOff))

	bundle := PolicyBundle{
		BundleID: "bad", Generation: 1, Mode: "full", IssuedAt: time.Now().UTC(),
		Rules: []RuleV2{{
			ID: "malformed", Enabled: true,
			Conditions: leaf(CondPath, "not_a_real_operator", "x"),
			Outcome:    Outcome{Verdict: VerdictAllow},
		}},
	}
	result, err := m.Apply(signedTestBundle(t, bundle))
	_ = err // a single bad RULE is a CompileIssue, not necessarily a hard Compile error

	// Either way, the bundle must not report Activated with the malformed
	// rule silently dropped and nothing else to show for it being empty.
	if result.Activated && len(result.Issues) == 0 {
		t.Errorf("expected either rejection or reported issues, got %+v", result)
	}

	// The ORIGINAL v1 rule set must still be in effect — the requester who
	// matched "abc" before Apply must still match after a bad Apply.
	resp := engine.Evaluate(ElevationRequest{AppHash: "abc", Now: time.Now()})
	if !resp.Allowed {
		t.Error("a rejected/partial bundle must not disturb the previously active policy")
	}
}

func TestBundleManager_Apply_FailingCanaryRejectsWholeBundle(t *testing.T) {
	engine := NewEngine(nil)
	st := newFakeBundleStore()
	m := NewBundleManager(engine, WithBundleStore(st), WithSignatureMode(SignatureModeOff))

	bundle := PolicyBundle{
		BundleID: "b-canary-fail", Generation: 1, Mode: "full", IssuedAt: time.Now().UTC(),
		Rules: []RuleV2{{
			ID: "allow-alice", Enabled: true,
			Conditions: leaf(CondUser, OpEquals, "alice"),
			Outcome:    Outcome{Verdict: VerdictAllow},
		}},
		Defaults: Defaults{Canaries: []Canary{
			{Name: "alice should be denied (deliberately wrong expectation)",
				Request: ElevationRequestV2{UserID: "alice"}, Expected: VerdictDeny},
		}},
	}
	result, err := m.Apply(signedTestBundle(t, bundle))
	if err == nil {
		t.Fatal("expected an error when a canary fails")
	}
	if result.Activated {
		t.Error("a bundle whose own canary fails must never activate")
	}

	active, _ := st.ActiveBundle()
	if active != nil {
		t.Errorf("no bundle should be active after a canary rejection, got %+v", active)
	}

	staged, err := st.GetBundle("b-canary-fail")
	if err != nil {
		t.Fatalf("GetBundle: %v", err)
	}
	if staged == nil || staged.State != "rejected" {
		t.Errorf("staged bundle state = %+v, want rejected", staged)
	}
}

func TestBundleManager_Apply_PassingCanaryActivates(t *testing.T) {
	engine := NewEngine(nil)
	st := newFakeBundleStore()
	m := NewBundleManager(engine, WithBundleStore(st), WithSignatureMode(SignatureModeOff))

	bundle := PolicyBundle{
		BundleID: "b-canary-pass", Generation: 1, Mode: "full", IssuedAt: time.Now().UTC(),
		Rules: []RuleV2{{
			ID: "allow-alice", Enabled: true,
			Conditions: leaf(CondUser, OpEquals, "alice"),
			Outcome:    Outcome{Verdict: VerdictAllow},
		}},
		Defaults: Defaults{Canaries: []Canary{
			{Name: "alice allowed", Request: ElevationRequestV2{UserID: "alice"}, Expected: VerdictAllow},
			{Name: "bob denied", Request: ElevationRequestV2{UserID: "bob"}, Expected: VerdictDeny},
		}},
	}
	result, err := m.Apply(signedTestBundle(t, bundle))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !result.Activated {
		t.Fatalf("expected activation, got %+v", result)
	}
}

func TestBundleManager_Apply_SignatureRequireRejectsUnsigned(t *testing.T) {
	engine := NewEngine([]PolicyRule{{ID: "keep-me", AppHash: "abc", Decision: DecisionAllow}})
	m := NewBundleManager(engine, WithSignatureMode(SignatureModeRequire))

	bundle := PolicyBundle{BundleID: "b1", Generation: 1, Mode: "full", IssuedAt: time.Now().UTC()}
	sb := signedTestBundle(t, bundle) // no signature at all

	result, err := m.Apply(sb)
	if err == nil {
		t.Fatal("expected an error under signature mode \"require\" with no valid signature")
	}
	if result.Activated {
		t.Error("must not activate an unsigned bundle under \"require\"")
	}
	if result.SigStatus != SigFailed {
		t.Errorf("SigStatus = %s, want failed", result.SigStatus)
	}

	resp := engine.Evaluate(ElevationRequest{AppHash: "abc", Now: time.Now()})
	if !resp.Allowed {
		t.Error("previous policy must remain in effect after a signature rejection")
	}
}

func TestBundleManager_Apply_SignatureWarnStillActivates(t *testing.T) {
	engine := NewEngine(nil)
	m := NewBundleManager(engine, WithSignatureMode(SignatureModeWarn))

	bundle := PolicyBundle{
		BundleID: "b1", Generation: 1, Mode: "full", IssuedAt: time.Now().UTC(),
		Rules: []RuleV2{{ID: "allow-alice", Enabled: true, Conditions: leaf(CondUser, OpEquals, "alice"), Outcome: Outcome{Verdict: VerdictAllow}}},
	}
	result, err := m.Apply(signedTestBundle(t, bundle)) // unsigned
	if err != nil {
		t.Fatalf("mode=warn must never itself return an error for a bad signature: %v", err)
	}
	if !result.Activated {
		t.Errorf("mode=warn must still activate despite a signature failure: %+v", result)
	}
	if result.SigStatus != SigFailed {
		t.Errorf("SigStatus = %s, want failed (recorded, not rejected)", result.SigStatus)
	}
}

func TestBundleManager_Apply_ValidSignatureVerifies(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	origKeys := PolicySigningKeys
	PolicySigningKeys = map[string]ed25519.PublicKey{"k1": pub}
	t.Cleanup(func() { PolicySigningKeys = origKeys })

	engine := NewEngine(nil)
	m := NewBundleManager(engine, WithSignatureMode(SignatureModeRequire))

	bundle := PolicyBundle{BundleID: "b1", Generation: 1, Mode: "full", IssuedAt: time.Now().UTC()}
	payload, _ := json.Marshal(bundle)
	sb := &SignedBundle{
		Payload: payload, KeyID: "k1",
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)),
	}

	result, err := m.Apply(sb)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if result.SigStatus != SigVerified {
		t.Errorf("SigStatus = %s, want verified", result.SigStatus)
	}
	if !result.Activated {
		t.Error("expected activation for a validly-signed bundle")
	}
}

// --- ApplyDelta ---

func TestApplyDelta_ParentMismatchRejected(t *testing.T) {
	base := &PolicyBundle{BundleID: "base-1", Generation: 1}
	delta := &PolicyBundle{BundleID: "delta-1", Generation: 2, Mode: "delta", ParentID: "not-base-1"}

	if _, err := ApplyDelta(base, delta); err == nil {
		t.Fatal("expected an error when delta.ParentID does not match base.BundleID")
	}
}

func TestApplyDelta_NonDeltaModeRejected(t *testing.T) {
	base := &PolicyBundle{BundleID: "base-1"}
	notDelta := &PolicyBundle{BundleID: "d1", Mode: "full", ParentID: "base-1"}
	if _, err := ApplyDelta(base, notDelta); err == nil {
		t.Fatal("expected an error when delta.Mode != \"delta\"")
	}
}

func TestApplyDelta_MergesAddsRemovesAndOverrides(t *testing.T) {
	base := &PolicyBundle{
		BundleID: "base-1", Generation: 1, Mode: "full",
		Rules: []RuleV2{
			{ID: "keep", Priority: 1},
			{ID: "remove-me", Priority: 1},
			{ID: "override-me", Priority: 1},
		},
	}
	delta := &PolicyBundle{
		BundleID: "delta-1", Generation: 2, Mode: "delta", ParentID: "base-1",
		Rules:      []RuleV2{{ID: "override-me", Priority: 99}, {ID: "brand-new", Priority: 1}},
		RemovedIDs: []string{"remove-me"},
	}

	merged, err := ApplyDelta(base, delta)
	if err != nil {
		t.Fatalf("ApplyDelta: %v", err)
	}
	if merged.BundleID != "delta-1" || merged.Generation != 2 || merged.Mode != "full" {
		t.Errorf("merged metadata = %+v, want delta-1/2/full", merged)
	}

	byID := make(map[string]RuleV2, len(merged.Rules))
	for _, r := range merged.Rules {
		byID[r.ID] = r
	}
	if _, ok := byID["remove-me"]; ok {
		t.Error("remove-me should have been removed")
	}
	if _, ok := byID["keep"]; !ok {
		t.Error("keep should have survived untouched")
	}
	if r, ok := byID["override-me"]; !ok || r.Priority != 99 {
		t.Errorf("override-me = %+v, want Priority=99 (delta's version)", r)
	}
	if _, ok := byID["brand-new"]; !ok {
		t.Error("brand-new should have been added")
	}
	if len(merged.Rules) != 3 {
		t.Errorf("merged.Rules = %v, want exactly 3 (keep, override-me, brand-new)", merged.Rules)
	}
}

func TestBundleManager_Apply_DeltaModeResolvesAgainstActiveBundle(t *testing.T) {
	engine := NewEngine(nil)
	st := newFakeBundleStore()
	m := NewBundleManager(engine, WithBundleStore(st), WithSignatureMode(SignatureModeOff))

	full := PolicyBundle{
		BundleID: "base-1", Generation: 1, Mode: "full", IssuedAt: time.Now().UTC(),
		Rules: []RuleV2{{ID: "allow-alice", Enabled: true, Conditions: leaf(CondUser, OpEquals, "alice"), Outcome: Outcome{Verdict: VerdictAllow}}},
	}
	if _, err := m.Apply(signedTestBundle(t, full)); err != nil {
		t.Fatalf("Apply(full): %v", err)
	}

	delta := PolicyBundle{
		BundleID: "delta-1", Generation: 2, Mode: "delta", ParentID: "base-1", IssuedAt: time.Now().UTC(),
		Rules: []RuleV2{{ID: "allow-bob", Enabled: true, Conditions: leaf(CondUser, OpEquals, "bob"), Outcome: Outcome{Verdict: VerdictAllow}}},
	}
	result, err := m.Apply(signedTestBundle(t, delta))
	if err != nil {
		t.Fatalf("Apply(delta): %v", err)
	}
	if !result.Activated {
		t.Fatalf("expected delta activation: %+v", result)
	}

	// Both the inherited rule and the delta-added rule must be in effect.
	if resp := engine.Evaluate(ElevationRequest{UserID: "alice", Now: time.Now()}); !resp.Allowed {
		t.Error("alice's rule (inherited from the base bundle) should still allow")
	}
	if resp := engine.Evaluate(ElevationRequest{UserID: "bob", Now: time.Now()}); !resp.Allowed {
		t.Error("bob's rule (added by the delta) should allow")
	}
}

func TestBundleManager_Apply_DeltaWithoutStoreFails(t *testing.T) {
	engine := NewEngine(nil)
	m := NewBundleManager(engine, WithSignatureMode(SignatureModeOff)) // no WithBundleStore

	delta := PolicyBundle{BundleID: "d1", Generation: 1, Mode: "delta", ParentID: "base-1", IssuedAt: time.Now().UTC()}
	if _, err := m.Apply(signedTestBundle(t, delta)); err == nil {
		t.Fatal("expected an error resolving a delta with no persistence configured")
	}
}

// --- Probation / crash-loop guard ---

func TestProbation_NoStateFileMeansNoRollback(t *testing.T) {
	shouldRollback, _ := CheckProbation(t.TempDir() + "/does-not-exist.json")
	if shouldRollback {
		t.Error("a missing state file must never trigger a rollback")
	}
}

func TestProbation_TriggersAfterThresholdWithinWindow(t *testing.T) {
	path := t.TempDir() + "/probation.json"
	for i := 0; i < probationBootThreshold-1; i++ {
		RecordBundleBoot(path, "bundle-x")
		if should, _ := CheckProbation(path); should {
			t.Fatalf("boot %d: should not trigger before threshold", i+1)
		}
	}
	RecordBundleBoot(path, "bundle-x")
	should, id := CheckProbation(path)
	if !should || id != "bundle-x" {
		t.Errorf("CheckProbation = (%v, %q), want (true, \"bundle-x\") after %d boots", should, id, probationBootThreshold)
	}
}

func TestProbation_DifferentBundleResetsCounter(t *testing.T) {
	path := t.TempDir() + "/probation.json"
	RecordBundleBoot(path, "bundle-x")
	RecordBundleBoot(path, "bundle-x")
	RecordBundleBoot(path, "bundle-y") // new bundle: counter resets
	should, _ := CheckProbation(path)
	if should {
		t.Error("a new bundle_id must reset the boot counter, not accumulate across bundles")
	}
}

func TestProbation_ClearsAfterStablePeriod(t *testing.T) {
	path := t.TempDir() + "/probation.json"
	state := &probationState{BundleID: "old-bundle", ActivatedAt: time.Now().Add(-probationClearAfter - time.Minute), BootCount: 5}
	if err := saveProbationState(path, state); err != nil {
		t.Fatal(err)
	}

	should, _ := CheckProbation(path)
	if should {
		t.Error("a bundle stable for longer than probationClearAfter must not trigger, regardless of boot count")
	}
	if _, err := loadProbationState(path); err == nil {
		t.Error("CheckProbation should have cleared the stale state file")
	}
}

func TestProbation_ClearProbationRemovesState(t *testing.T) {
	path := t.TempDir() + "/probation.json"
	RecordBundleBoot(path, "bundle-x")
	ClearProbation(path)
	if _, err := loadProbationState(path); err == nil {
		t.Error("expected the state file to be removed")
	}
}

func TestBundleManager_ApplyResetsProbationWindow(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/probation.json"

	engine := NewEngine(nil)
	m := NewBundleManager(engine, WithSignatureMode(SignatureModeOff), WithProbationPath(path))

	bundle := PolicyBundle{BundleID: "fresh-bundle", Generation: 1, Mode: "full", IssuedAt: time.Now().UTC()}
	if _, err := m.Apply(signedTestBundle(t, bundle)); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	state, err := loadProbationState(path)
	if err != nil {
		t.Fatalf("loadProbationState: %v", err)
	}
	if state.BundleID != "fresh-bundle" || state.BootCount != 1 {
		t.Errorf("state = %+v, want BundleID=fresh-bundle BootCount=1", state)
	}
}
