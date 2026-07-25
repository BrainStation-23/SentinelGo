package native

import (
	"context"
	"encoding/json"
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

// Run parses the "rules" field of the task payload into policy rules, upserts
// them into the local EPM store, and prunes any previously cached rule that is
// no longer present in this (full) rule set. This mirrors sync-software's
// upsert-then-DeleteNotIn pattern so a full resync always converges the local
// cache to exactly what the server last sent.
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
func parseEPMRules(payload map[string]interface{}) ([]epm.PolicyRule, error) {
	raw, ok := payload["rules"]
	if !ok || raw == nil {
		return nil, nil
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
