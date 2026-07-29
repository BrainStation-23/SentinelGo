package native

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	"sentinelgo/internal/config"
	"sentinelgo/internal/epm"
	"sentinelgo/internal/sanitize"
	"sentinelgo/internal/store"
	"sentinelgo/internal/taskstore"
)

// openEPMStoreFn opens the local EPM policy cache. Replaced in tests.
var openEPMStoreFn = func(cfg *config.Config) (*store.EPMStore, error) {
	dbPath := filepath.Join(filepath.Dir(cfg.Path), store.EPMDBName)
	return store.NewEPMStore(dbPath)
}

type epmPolicySyncHandler struct{}

func init() { Register(&epmPolicySyncHandler{}) }

func (h *epmPolicySyncHandler) Slugs() []string {
	return []string{"epm-policy-sync"}
}

// errNoRulesKey reports a payload with no usable "rules" entry. It is a task
// failure, never an empty rule set — see parseEPMRules.
var errNoRulesKey = errors.New(`payload has no "rules" key`)

// Run parses the "rules" field of the task payload into policy rules, upserts
// them into the local EPM store, and prunes any previously cached rule that is
// no longer present in this (full) rule set. This mirrors sync-software's
// upsert-then-DeleteNotIn pattern so a full resync always converges the local
// cache to exactly what the server last sent.
//
// An explicitly empty rule set ("rules": []) is a legitimate instruction to
// clear local policy and takes the PruneAll path. A payload that simply lacks
// the key fails the task instead, leaving the cache untouched; see
// parseEPMRules and store.EPMStore.PruneAll for why the distinction matters.
func (h *epmPolicySyncHandler) Run(_ context.Context, cfg *config.Config, task taskstore.Task) (string, error) {
	rules, err := parseEPMRules(task.Payload)
	if err != nil {
		return "", fmt.Errorf("epm-policy-sync: parse rules: %w", err)
	}

	st, err := openEPMStoreFn(cfg)
	if err != nil {
		return "", fmt.Errorf("epm-policy-sync: open store: %w", err)
	}
	defer func() { _ = st.Close() }()

	if len(rules) == 0 {
		if err := st.PruneAll(); err != nil {
			return "", fmt.Errorf("epm-policy-sync: prune rules: %w", err)
		}
		return "epm policy synced successfully: 0 rules (policy cleared)", nil
	}

	if err := st.UpsertRules(rules); err != nil {
		return "", fmt.Errorf("epm-policy-sync: upsert rules: %w", err)
	}

	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
	}
	if err := st.DeleteRulesNotIn(ids); err != nil {
		return "", fmt.Errorf("epm-policy-sync: prune rules: %w", err)
	}

	count := sanitize.ForLog(fmt.Sprintf("%d", len(rules)))
	return fmt.Sprintf("epm policy synced successfully: %s rules", count), nil
}

// parseEPMRules extracts and decodes the "rules" entry of a task payload.
// task.Payload arrives as map[string]interface{} straight off JSON, so the
// round-trip through json.Marshal/Unmarshal is the same idiom used elsewhere
// to turn a loosely-typed payload value into a concrete Go type (see
// executor.go's payload handling).
//
// A missing or null "rules" key returns errNoRulesKey rather than an empty
// slice. The two are not interchangeable: because this handler treats an empty
// rule set as "clear all local policy", and policy evaluation is default-deny,
// silently reading a malformed or truncated payload as "zero rules" would wipe
// the cache and lock every user out of every elevation until the next
// successful sync. Absent must fail the task; only an explicit "rules": []
// clears policy.
func parseEPMRules(payload map[string]interface{}) ([]epm.PolicyRule, error) {
	raw, ok := payload["rules"]
	if !ok || raw == nil {
		return nil, errNoRulesKey
	}

	data, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("marshal rules payload: %w", err)
	}

	var rules []epm.PolicyRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("unmarshal rules payload: %w", err)
	}
	return rules, nil
}
