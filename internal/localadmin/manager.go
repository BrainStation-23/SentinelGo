package localadmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"sentinelgo/internal/config"
)

// StoreFile is the grant store, next to config.json.
const StoreFile = "local_admin_grants.json"

// Grant states, as reported in the inventory's admin_grants.
const (
	GrantActive  = "active"
	GrantRemoved = "removed"
	GrantFailed  = "failed" // the removal failed; it is retried
)

// keepRemoved is how long a removed grant stays in the report.
const keepRemoved = 7 * 24 * time.Hour

// clockSlack is how far the wall clock may sit before a grant's start
// before that is treated as the clock being set back.
const clockSlack = 5 * time.Minute

// Grant is one time-limited grant the agent enforces.
type Grant struct {
	GrantID   string     `json:"grant_id"`
	Member    string     `json:"member"`
	SID       string     `json:"sid,omitempty"`
	Source    string     `json:"source,omitempty"`
	SignOut   bool       `json:"sign_out,omitempty"`
	GrantedAt time.Time  `json:"granted_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	State     string     `json:"state"`
	RemovedAt *time.Time `json:"removed_at,omitempty"`
	Error     string     `json:"error,omitempty"`
	Attempts  int        `json:"attempts,omitempty"`
	NextTry   time.Time  `json:"next_try,omitempty"`
	Backup    bool       `json:"backup,omitempty"` // a backup OS task exists
}

// GrantReport is a grant as sent in the inventory (admin_grants).
type GrantReport struct {
	GrantID   string     `json:"grant_id"`
	Member    string     `json:"member"`
	ExpiresAt time.Time  `json:"expires_at"`
	State     string     `json:"state"`
	RemovedAt *time.Time `json:"removed_at,omitempty"`
	Error     string     `json:"error,omitempty"`
}

type storeData struct {
	Grants []Grant `json:"grants"`
	// HighWater is the latest wall time the agent has seen. "Now" is never
	// earlier than it, so setting the clock back doesn't extend a grant.
	HighWater time.Time `json:"high_water"`
}

func (g Grant) request() Request {
	return Request{Member: g.Member, SID: g.SID, Source: g.Source, SignOut: g.SignOut, GrantID: g.GrantID}
}

// sameAccount reports whether a request names the grant's account.
func (g Grant) sameAccount(r Request) bool {
	if g.SID != "" && r.SID != "" {
		return g.SID == r.SID
	}
	return g.Member == r.Member && g.Source == r.Source
}

// monoMark is when this process first saw a grant, on the monotonic clock,
// and how long it had left then.
type monoMark struct {
	at   time.Time
	left time.Duration
}

// Manager applies local admin changes and enforces expiries. One per config
// directory and process (ForConfigDir); its methods are safe for concurrent
// use, and the store is re-read on every operation, so a backup task's
// "expire" in another process is seen.
type Manager struct {
	mu     sync.Mutex
	path   string
	group  Group
	backup Backup
	now    func() time.Time // wall clock; tests replace it
	since  func(time.Time) time.Duration
	marks  map[string]monoMark
}

// NewManager returns a manager with explicit parts (tests).
func NewManager(path string, group Group, backup Backup) *Manager {
	return &Manager{path: path, group: group, backup: backup, now: time.Now, since: time.Since, marks: map[string]monoMark{}}
}

// StorePath is the grant store in a config directory.
func StorePath(dir string) string { return filepath.Join(dir, StoreFile) }

func (m *Manager) load() (storeData, error) {
	var d storeData
	b, err := os.ReadFile(m.path)
	if errors.Is(err, os.ErrNotExist) {
		return d, nil
	}
	if err != nil {
		return d, err
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return storeData{}, fmt.Errorf("local admin grant store is unreadable: %w", err)
	}
	return d, nil
}

// save writes the store atomically and locks it down like config.json.
func (m *Manager) save(d storeData) error {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := config.SecureFile(tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, m.path)
}

// nowLocked is the effective time: the wall clock, but never earlier than
// the latest time already seen.
func (m *Manager) nowLocked(d *storeData) time.Time {
	now := m.now()
	if now.Before(d.HighWater) {
		return d.HighWater
	}
	return now
}

// Apply runs one task: add (with an optional expiry) or remove.
func (m *Manager) Apply(ctx context.Context, add bool, r Request) (Outcome, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.load()
	if err != nil {
		return Outcome{}, err
	}
	if add {
		return m.addLocked(ctx, &d, r)
	}
	return m.removeLocked(ctx, &d, r)
}

func (m *Manager) addLocked(ctx context.Context, d *storeData, r Request) (Outcome, error) {
	now := m.nowLocked(d)
	if r.ExpiresAt == nil {
		return m.group.Add(ctx, r)
	}
	if !r.ExpiresAt.After(now) {
		return Outcome{}, fmt.Errorf("expires_at is in the past")
	}
	// An open grant for the same account is an extension: the account is
	// an administrator because of it, so "already" doesn't apply.
	idx := -1
	for i, g := range d.Grants {
		if g.State != GrantRemoved && (g.GrantID == r.GrantID || g.sameAccount(r)) {
			idx = i
			break
		}
	}
	if idx < 0 {
		member, err := m.group.IsMember(ctx, r)
		if err != nil {
			return Outcome{}, err
		}
		if member {
			return Outcome{}, ErrAlreadyAdmin
		}
	}
	out, err := m.group.Add(ctx, r)
	if err != nil {
		return Outcome{}, err
	}
	g := Grant{GrantID: r.GrantID, Member: r.Member, SID: r.SID, Source: r.Source, GrantedAt: now, ExpiresAt: r.ExpiresAt.UTC(), State: GrantActive}
	if idx >= 0 {
		g.GrantedAt, g.SignOut = d.Grants[idx].GrantedAt, d.Grants[idx].SignOut
		if d.Grants[idx].GrantID != r.GrantID && d.Grants[idx].Backup {
			_ = m.backup.Cancel(ctx, d.Grants[idx].GrantID)
		}
		d.Grants[idx] = g
	} else {
		d.Grants = append(d.Grants, g)
		idx = len(d.Grants) - 1
	}
	delete(m.marks, g.GrantID)
	if err := m.backup.Schedule(ctx, g.GrantID, g.ExpiresAt); err != nil {
		log.Printf("local admin: backup task for grant %s not created: %v", g.GrantID, err)
		out.Note = "the backup expiry task couldn't be created; the agent's own timer still ends the grant"
	} else {
		d.Grants[idx].Backup = true
	}
	if err := m.save(*d); err != nil {
		// The rights were given but the expiry isn't recorded: take them
		// back rather than leave an admin nobody will remove.
		_, rerr := m.group.Remove(ctx, r)
		return Outcome{}, fmt.Errorf("couldn't record the grant's expiry (%w); the rights were taken back (%v)", err, rerr)
	}
	return out, nil
}

func (m *Manager) removeLocked(ctx context.Context, d *storeData, r Request) (Outcome, error) {
	out, err := m.group.Remove(ctx, r)
	if err != nil {
		return Outcome{}, err
	}
	now := m.nowLocked(d)
	changed := false
	for i := range d.Grants {
		g := &d.Grants[i]
		if g.State == GrantRemoved || (g.GrantID != r.GrantID && !g.sameAccount(r)) {
			continue
		}
		m.markRemoved(ctx, g, now)
		changed = true
	}
	if changed {
		if err := m.save(*d); err != nil {
			log.Printf("local admin: grant store not updated: %v", err)
		}
	}
	return out, nil
}

func (m *Manager) markRemoved(ctx context.Context, g *Grant, now time.Time) {
	t := now.UTC()
	g.State, g.RemovedAt, g.Error, g.NextTry = GrantRemoved, &t, "", time.Time{}
	if g.Backup {
		if err := m.backup.Cancel(ctx, g.GrantID); err != nil {
			log.Printf("local admin: backup task for grant %s not removed: %v", g.GrantID, err)
		}
		g.Backup = false
	}
	delete(m.marks, g.GrantID)
}

// due reports whether g has expired: on the effective wall clock, on this
// process's monotonic clock, or, when the wall clock reads earlier than the
// grant's start, because the clock was set back ("on doubt, remove").
func (m *Manager) due(g Grant, now time.Time) bool {
	if !now.Before(g.ExpiresAt) || m.now().Before(g.GrantedAt.Add(-clockSlack)) {
		return true
	}
	mk, ok := m.marks[g.GrantID]
	if !ok {
		m.marks[g.GrantID] = monoMark{at: time.Now(), left: g.ExpiresAt.Sub(now)}
		return false
	}
	return m.since(mk.at) >= mk.left
}

// Check removes the rights of every grant that is due, and prunes removed
// grants older than keepRemoved. It needs no server.
func (m *Manager) Check(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.load()
	if err != nil {
		log.Printf("local admin: %v", err)
		return
	}
	m.checkLocked(ctx, &d, "")
}

// Expire removes one grant's rights if it is due (the backup task's path).
func (m *Manager) Expire(ctx context.Context, grantID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.load()
	if err != nil {
		return "", err
	}
	for _, g := range d.Grants {
		if g.GrantID != grantID {
			continue
		}
		if g.State == GrantRemoved {
			if err := m.backup.Cancel(ctx, grantID); err != nil {
				log.Printf("local admin: backup task for grant %s not removed: %v", grantID, err)
			}
			return GrantRemoved, nil
		}
		m.checkLocked(ctx, &d, grantID)
		for _, g2 := range d.Grants {
			if g2.GrantID == grantID {
				return g2.State, nil
			}
		}
	}
	_ = m.backup.Cancel(ctx, grantID)
	return "", fmt.Errorf("no grant %s on this device", grantID)
}

// checkLocked handles due grants (only grantID when set; it is then retried
// at once even while backing off).
func (m *Manager) checkLocked(ctx context.Context, d *storeData, only string) {
	now := m.nowLocked(d)
	changed := false
	if wall := m.now(); wall.Sub(d.HighWater) >= time.Minute {
		d.HighWater, changed = wall.UTC(), true
	}
	kept := d.Grants[:0]
	for _, g := range d.Grants {
		if g.State == GrantRemoved && g.RemovedAt != nil && now.Sub(*g.RemovedAt) > keepRemoved {
			changed = true
			continue
		}
		if g.State != GrantRemoved && (only == "" || g.GrantID == only) && m.due(g, now) &&
			(only != "" || !now.Before(g.NextTry)) {
			m.expireLocked(ctx, &g, now)
			changed = true
		}
		kept = append(kept, g)
	}
	d.Grants = kept
	if changed {
		if err := m.save(*d); err != nil {
			log.Printf("local admin: grant store not saved: %v", err)
		}
	}
}

// retryDelay backs off a failing removal: 30 s, 1 min, 2 min, … up to 1 h.
func retryDelay(attempts int) time.Duration {
	d := 30 * time.Second
	for i := 1; i < attempts && d < time.Hour; i++ {
		d *= 2
	}
	return min(d, time.Hour)
}

func (m *Manager) expireLocked(ctx context.Context, g *Grant, now time.Time) {
	out, err := m.group.Remove(ctx, g.request())
	if err != nil {
		g.State, g.Error = GrantFailed, err.Error()
		g.Attempts++
		g.NextTry = now.Add(retryDelay(g.Attempts))
		log.Printf("local admin: removing %s at the end of grant %s failed (attempt %d): %v", g.Member, g.GrantID, g.Attempts, err)
		return
	}
	log.Printf("local admin: grant %s ended: %s %s", g.GrantID, g.Member, out.State)
	m.markRemoved(ctx, g, now)
}

// Run checks at start (a deadline missed while the agent was down is
// handled at once) and then every interval. Checking the wall clock on each
// tick also covers resume from sleep.
func (m *Manager) Run(ctx context.Context, interval time.Duration) {
	m.Check(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Check(ctx)
		}
	}
}

// Report reads a store's grants for the inventory, without removed ones
// older than keepRemoved. nil when there are none.
func Report(path string, now time.Time) []GrantReport {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var d storeData
	if json.Unmarshal(b, &d) != nil {
		return nil
	}
	var out []GrantReport
	for _, g := range d.Grants {
		if g.State == GrantRemoved && g.RemovedAt != nil && now.Sub(*g.RemovedAt) > keepRemoved {
			continue
		}
		out = append(out, GrantReport{GrantID: g.GrantID, Member: g.Member, ExpiresAt: g.ExpiresAt, State: g.State, RemovedAt: g.RemovedAt, Error: g.Error})
	}
	return out
}
