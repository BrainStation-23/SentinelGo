package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"sentinelgo/internal/epm"
)

// Compile-time proof that *EPMStore satisfies BundleManager's persistence
// seam structurally — see BundleRow's doc comment for why this works without
// any adapter code, and why it would silently stop compiling (rather than
// silently failing at runtime) if a method signature here ever drifted from
// epm.BundlePersistence's.
var _ epm.BundlePersistence = (*EPMStore)(nil)

// Bundle states, mirroring epm.SigStatus's role for signatures — see
// BundleManager (internal/epm/bundle_manager.go) for the state machine:
// staged -> active -> superseded, or staged -> rejected, or
// active -> rolled_back.
const (
	BundleStateStaged     = "staged"
	BundleStateActive     = "active"
	BundleStateSuperseded = "superseded"
	BundleStateRolledBack = "rolled_back"
	BundleStateRejected   = "rejected"
)

// BundleRow is the epm_bundles row shape (schema v3, store/schema_epm_v3.go).
// A type alias — not a new struct — for epm.BundleRecord: BundleManager's
// BundlePersistence interface (internal/epm/bundle_manager.go) is expressed
// in terms of epm.BundleRecord specifically so *EPMStore satisfies it
// structurally, method-for-method, with zero adapter code. internal/store
// already imports internal/epm (for RuleV2/RuleGroup/PolicyRule elsewhere in
// this package), so referencing an epm-declared type here creates no cycle;
// the reverse — epm importing a store-declared type — would.
type BundleRow = epm.BundleRecord

// InsertBundle stages a new bundle row. Callers (BundleManager.Apply) insert
// with State=BundleStateStaged and only move it to active via ActivateBundle,
// so a bundle that fails compilation or its canary suite never becomes
// active in the first place.
func (s *EPMStore) InsertBundle(row BundleRow) error {
	_, err := s.db.Exec(`
		INSERT INTO epm_bundles
			(bundle_id, generation, parent_id, tenant_id, mode, schema_version,
			 issued_at, not_after, key_id, signature, sig_status, payload,
			 received_at, applied_at, state)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(bundle_id) DO UPDATE SET
			generation = excluded.generation, sig_status = excluded.sig_status,
			state = excluded.state
	`,
		row.BundleID, row.Generation, row.ParentID, row.TenantID, row.Mode, row.SchemaVersion,
		formatExpiresAt(row.IssuedAt), formatExpiresAt(row.NotAfter), row.KeyID, row.Signature, row.SigStatus, row.Payload,
		formatExpiresAt(row.ReceivedAt), formatExpiresAt(row.AppliedAt), row.State,
	)
	if err != nil {
		return fmt.Errorf("insert epm bundle %q: %w", row.BundleID, err)
	}
	return nil
}

// SetBundleState updates a single bundle's lifecycle state — used for the
// staged->rejected and active->rolled_back transitions, which (unlike
// activation) never need to touch any other row atomically.
func (s *EPMStore) SetBundleState(bundleID, state string) error {
	res, err := s.db.Exec(`UPDATE epm_bundles SET state = ? WHERE bundle_id = ?`, state, bundleID)
	if err != nil {
		return fmt.Errorf("set epm bundle %q state: %w", bundleID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("set epm bundle state: no bundle %q", bundleID)
	}
	return nil
}

// ActivateBundle atomically supersedes whatever bundle is currently active
// (state 'active' -> 'superseded') and marks bundleID active, so exactly one
// bundle is ever active at a time even if the process crashes mid-call: the
// whole thing is one transaction, so a crash either leaves the previous
// bundle active (transaction never committed) or the new one active
// (committed) — never both, never neither.
func (s *EPMStore) ActivateBundle(bundleID string, appliedAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin activate bundle tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			log.Printf("EPMStore: rollback: %v", err)
		}
	}()

	if _, err := tx.Exec(`UPDATE epm_bundles SET state = ? WHERE state = ?`,
		BundleStateSuperseded, BundleStateActive); err != nil {
		return fmt.Errorf("supersede previous active bundle: %w", err)
	}
	res, err := tx.Exec(`UPDATE epm_bundles SET state = ?, applied_at = ? WHERE bundle_id = ?`,
		BundleStateActive, formatExpiresAt(appliedAt), bundleID)
	if err != nil {
		return fmt.Errorf("activate bundle %q: %w", bundleID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("activate bundle: no bundle %q", bundleID)
	}
	return tx.Commit()
}

// ActiveBundle returns the currently active bundle, or nil if none.
func (s *EPMStore) ActiveBundle() (*BundleRow, error) {
	return s.queryOneBundle(`SELECT `+bundleColumns+` FROM epm_bundles WHERE state = ? LIMIT 1`, BundleStateActive)
}

// GetBundle returns one bundle by ID, or nil if not found.
func (s *EPMStore) GetBundle(bundleID string) (*BundleRow, error) {
	return s.queryOneBundle(`SELECT `+bundleColumns+` FROM epm_bundles WHERE bundle_id = ?`, bundleID)
}

// BundleByGeneration returns the bundle at a specific generation, or nil if
// none — used by the operator-initiated rollback task (payload
// {"generation": N}).
func (s *EPMStore) BundleByGeneration(generation int64) (*BundleRow, error) {
	return s.queryOneBundle(`SELECT `+bundleColumns+` FROM epm_bundles WHERE generation = ?`, generation)
}

// PreviousActiveBundle returns the most recently superseded bundle (the one
// a rollback reverts TO by default) — the highest-generation row currently
// in state 'superseded'.
func (s *EPMStore) PreviousActiveBundle() (*BundleRow, error) {
	return s.queryOneBundle(
		`SELECT `+bundleColumns+` FROM epm_bundles WHERE state = ? ORDER BY generation DESC LIMIT 1`,
		BundleStateSuperseded)
}

const bundleColumns = `bundle_id, generation, parent_id, tenant_id, mode, schema_version,
	issued_at, not_after, key_id, signature, sig_status, payload, received_at, applied_at, state`

func (s *EPMStore) queryOneBundle(query string, args ...any) (*BundleRow, error) {
	row := s.db.QueryRow(query, args...)
	var r BundleRow
	var issuedAt, notAfter, receivedAt, appliedAt string
	err := row.Scan(
		&r.BundleID, &r.Generation, &r.ParentID, &r.TenantID, &r.Mode, &r.SchemaVersion,
		&issuedAt, &notAfter, &r.KeyID, &r.Signature, &r.SigStatus, &r.Payload,
		&receivedAt, &appliedAt, &r.State,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query epm bundle: %w", err)
	}
	r.IssuedAt = parseExpiresAt(issuedAt)
	r.NotAfter = parseExpiresAt(notAfter)
	r.ReceivedAt = parseExpiresAt(receivedAt)
	r.AppliedAt = parseExpiresAt(appliedAt)
	return &r, nil
}

// PruneBundles deletes every non-active bundle beyond the keep most recent
// (by generation) superseded/rejected/rolled_back rows — the active bundle
// and its rules are never pruned. Also deletes the corresponding
// epm_rules_v2/epm_rule_groups rows (foreign-key-less by design, matching
// this package's existing schema, so the delete is explicit).
func (s *EPMStore) PruneBundles(keep int) error {
	if keep < 1 {
		keep = 1
	}
	rows, err := s.db.Query(
		`SELECT bundle_id FROM epm_bundles WHERE state != ? ORDER BY generation DESC`,
		BundleStateActive,
	)
	if err != nil {
		return fmt.Errorf("query prunable bundles: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan bundle id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_ = rows.Close()

	if len(ids) <= keep {
		return nil
	}
	toDelete := ids[keep:]

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin prune bundles tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			log.Printf("EPMStore: rollback: %v", err)
		}
	}()

	placeholders := strings.Repeat("?,", len(toDelete))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, len(toDelete))
	for i, id := range toDelete {
		args[i] = id
	}
	// #nosec G202 - placeholders is generated from strings.Repeat with only "?" and "," characters
	for _, table := range []string{"epm_rules_v2", "epm_rule_groups", "epm_bundles"} {
		if _, err := tx.Exec("DELETE FROM "+table+" WHERE bundle_id IN ("+placeholders+")", args...); err != nil {
			return fmt.Errorf("prune %s: %w", table, err)
		}
	}
	return tx.Commit()
}

// --- epm_rules_v2 / epm_rule_groups ---

// UpsertRulesV2 replaces every RuleV2 belonging to bundleID with rules,
// serializing each rule's Conditions tree and Outcome as JSON columns.
func (s *EPMStore) UpsertRulesV2(bundleID string, rules []epm.RuleV2) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin upsert rules_v2 tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			log.Printf("EPMStore: rollback: %v", err)
		}
	}()

	if _, err := tx.Exec(`DELETE FROM epm_rules_v2 WHERE bundle_id = ?`, bundleID); err != nil {
		return fmt.Errorf("clear existing rules_v2: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	stmt, err := tx.Prepare(`
		INSERT INTO epm_rules_v2
			(bundle_id, id, group_id, version, enabled, priority, conditions, outcome,
			 effective_from, expires_at, on_unknown, labels, static_spec, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare insert rules_v2: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, r := range rules {
		conditions, err := json.Marshal(r.Conditions)
		if err != nil {
			return fmt.Errorf("marshal conditions for rule %q: %w", r.ID, err)
		}
		outcome, err := json.Marshal(r.Outcome)
		if err != nil {
			return fmt.Errorf("marshal outcome for rule %q: %w", r.ID, err)
		}
		labels, err := json.Marshal(r.Labels)
		if err != nil {
			return fmt.Errorf("marshal labels for rule %q: %w", r.ID, err)
		}
		enabled := 0
		if r.Enabled {
			enabled = 1
		}
		if _, err := stmt.Exec(
			bundleID, r.ID, r.GroupID, r.Version, enabled, r.Priority,
			string(conditions), string(outcome),
			formatExpiresAt(r.EffectiveFrom), formatExpiresAt(r.ExpiresAt), r.OnUnknown, string(labels),
			0, now, now,
		); err != nil {
			return fmt.Errorf("insert rule %q: %w", r.ID, err)
		}
	}
	return tx.Commit()
}

// GetRulesV2 returns every RuleV2 belonging to bundleID, ordered by id for
// the same determinism reason store.EPMStore.GetRules orders v1 rules.
func (s *EPMStore) GetRulesV2(bundleID string) ([]epm.RuleV2, error) {
	rows, err := s.db.Query(`
		SELECT id, group_id, version, enabled, priority, conditions, outcome,
		       effective_from, expires_at, on_unknown, labels
		FROM epm_rules_v2 WHERE bundle_id = ? ORDER BY id ASC
	`, bundleID)
	if err != nil {
		return nil, fmt.Errorf("query rules_v2: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []epm.RuleV2
	for rows.Next() {
		var r epm.RuleV2
		var enabled int
		var conditions, outcome, labels string
		var effectiveFrom, expiresAt string
		if err := rows.Scan(
			&r.ID, &r.GroupID, &r.Version, &enabled, &r.Priority, &conditions, &outcome,
			&effectiveFrom, &expiresAt, &r.OnUnknown, &labels,
		); err != nil {
			return nil, fmt.Errorf("scan rule_v2 row: %w", err)
		}
		r.Enabled = enabled != 0
		if conditions != "" && conditions != "null" {
			if err := json.Unmarshal([]byte(conditions), &r.Conditions); err != nil {
				return nil, fmt.Errorf("unmarshal conditions for rule %q: %w", r.ID, err)
			}
		}
		if outcome != "" {
			if err := json.Unmarshal([]byte(outcome), &r.Outcome); err != nil {
				return nil, fmt.Errorf("unmarshal outcome for rule %q: %w", r.ID, err)
			}
		}
		if labels != "" && labels != "null" {
			if err := json.Unmarshal([]byte(labels), &r.Labels); err != nil {
				return nil, fmt.Errorf("unmarshal labels for rule %q: %w", r.ID, err)
			}
		}
		r.EffectiveFrom = parseExpiresAt(effectiveFrom)
		r.ExpiresAt = parseExpiresAt(expiresAt)
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpsertRuleGroups replaces every RuleGroup belonging to bundleID.
func (s *EPMStore) UpsertRuleGroups(bundleID string, groups []epm.RuleGroup) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin upsert rule_groups tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			log.Printf("EPMStore: rollback: %v", err)
		}
	}()

	if _, err := tx.Exec(`DELETE FROM epm_rule_groups WHERE bundle_id = ?`, bundleID); err != nil {
		return fmt.Errorf("clear existing rule_groups: %w", err)
	}

	stmt, err := tx.Prepare(`
		INSERT INTO epm_rule_groups (bundle_id, id, name, enabled, priority, conditions, defaults)
		VALUES (?, ?, ?, ?, ?, ?, '')
	`)
	if err != nil {
		return fmt.Errorf("prepare insert rule_groups: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, g := range groups {
		conditions, err := json.Marshal(g.Conditions)
		if err != nil {
			return fmt.Errorf("marshal conditions for group %q: %w", g.ID, err)
		}
		enabled := 0
		if g.Enabled {
			enabled = 1
		}
		if _, err := stmt.Exec(bundleID, g.ID, g.Name, enabled, g.Priority, string(conditions)); err != nil {
			return fmt.Errorf("insert rule group %q: %w", g.ID, err)
		}
	}
	return tx.Commit()
}

// GetRuleGroups returns every RuleGroup belonging to bundleID.
func (s *EPMStore) GetRuleGroups(bundleID string) ([]epm.RuleGroup, error) {
	rows, err := s.db.Query(`
		SELECT id, name, enabled, priority, conditions FROM epm_rule_groups WHERE bundle_id = ? ORDER BY id ASC
	`, bundleID)
	if err != nil {
		return nil, fmt.Errorf("query rule_groups: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []epm.RuleGroup
	for rows.Next() {
		var g epm.RuleGroup
		var enabled int
		var conditions string
		if err := rows.Scan(&g.ID, &g.Name, &enabled, &g.Priority, &conditions); err != nil {
			return nil, fmt.Errorf("scan rule_group row: %w", err)
		}
		g.Enabled = enabled != 0
		if conditions != "" && conditions != "null" {
			if err := json.Unmarshal([]byte(conditions), &g.Conditions); err != nil {
				return nil, fmt.Errorf("unmarshal conditions for group %q: %w", g.ID, err)
			}
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
