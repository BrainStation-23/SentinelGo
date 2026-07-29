package native

import (
	"context"
	"fmt"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/store"
	"sentinelgo/internal/taskstore"
)

// epmPolicyRollbackHandler implements the operator-initiated half of Phase
// 3's two rollback mechanisms (the other being the automatic crash-loop
// guard — epm.CheckProbation/RecordBundleBoot, wired at agent startup). This
// one only updates the local bundle store's state (target generation ->
// active, whatever was active -> rolled_back) — it does not itself reach into
// a live *epm.Engine, for the same reason epm-policy-sync's v1 path does not
// either: the native task Handler interface (Run(ctx, cfg, task)) has no way
// to receive a reference to the running enforcement Server's Engine. A v1
// rule set already tolerates this because PipeServer/SocketServer re-read
// RuleProvider.GetRules() fresh on every request by default; a bundle-backed
// deployment gets the same "takes effect on the next request" behavior only
// if the Server was constructed with WithEngine pointed at a *BundleManager*-
// owned Engine and something re-Swaps it after this task runs — wiring that
// belongs to whatever integrates BundleManager into main_integration.go
// (naturally alongside Phase 7's backend fetch, since there is no bundle
// distribution path to receive a *new* one from yet either).
type epmPolicyRollbackHandler struct{}

func init() { Register(&epmPolicyRollbackHandler{}) }

func (h *epmPolicyRollbackHandler) Slugs() []string {
	return []string{"epm-policy-rollback"}
}

// Run reads {"generation": N} from the task payload and, if a bundle at that
// generation exists, marks it active and marks whichever bundle was
// previously active as rolled_back — via store.EPMStore.ActivateBundle's
// same atomic supersede-then-activate transaction BundleManager.Apply uses,
// so this can never leave two bundles simultaneously active or the store
// briefly without any active bundle.
func (h *epmPolicyRollbackHandler) Run(_ context.Context, cfg *config.Config, task taskstore.Task) (string, error) {
	generation, err := parseRollbackGeneration(task.Payload)
	if err != nil {
		return "", fmt.Errorf("epm-policy-rollback: %w", err)
	}

	st, err := openEPMStoreFn(cfg)
	if err != nil {
		return "", fmt.Errorf("epm-policy-rollback: open store: %w", err)
	}
	defer func() { _ = st.Close() }()

	target, err := st.BundleByGeneration(generation)
	if err != nil {
		return "", fmt.Errorf("epm-policy-rollback: look up generation %d: %w", generation, err)
	}
	if target == nil {
		return "", fmt.Errorf("epm-policy-rollback: no bundle at generation %d", generation)
	}
	if target.State == store.BundleStateActive {
		return fmt.Sprintf("epm-policy-rollback: generation %d (%s) is already active", generation, target.BundleID), nil
	}

	if err := st.ActivateBundle(target.BundleID, epmRollbackNowFn()); err != nil {
		return "", fmt.Errorf("epm-policy-rollback: activate generation %d: %w", generation, err)
	}

	return fmt.Sprintf("epm-policy-rollback: rolled back to generation %d (%s)", generation, target.BundleID), nil
}

// epmRollbackNowFn is a seam so tests get a deterministic timestamp.
var epmRollbackNowFn = func() time.Time { return time.Now().UTC() }

func parseRollbackGeneration(payload map[string]interface{}) (int64, error) {
	raw, ok := payload["generation"]
	if !ok || raw == nil {
		return 0, fmt.Errorf(`payload has no "generation" key`)
	}
	switch v := raw.(type) {
	case float64: // task payloads decode JSON numbers as float64
		return int64(v), nil
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	default:
		return 0, fmt.Errorf("generation must be a number, got %T", raw)
	}
}
