package filedlp

// Overrides (#336 part 2, Compliance-OS#581): a file blocked by a
// block_override policy may go through after its user gives a reason. The
// agent then allows that file (by its content hash) for that user on that
// channel for a short while, so the user's retry succeeds, and records an
// "overridden" event with the reason. A user may override at most
// override_daily_limit times a day on this device.

import (
	"errors"
	"strings"
	"sync"
	"time"

	"sentinelgo/internal/dlp/events"
)

// overrideAllowFor is how long an override lets the same file through.
const overrideAllowFor = 10 * time.Minute

// pendingKeep is how long a blocked file can still be overridden.
const pendingKeep = 15 * time.Minute

// Bounds on what is kept in memory.
const (
	maxOverrideGrants = 1024
	maxPendingBlocks  = 256
)

// Override errors, shown to the user.
var (
	ErrOverrideLimit   = errors.New("you have used all the overrides allowed today")
	ErrOverrideUnknown = errors.New("this block can no longer be overridden; copy the file again")
	ErrOverrideReason  = errors.New("a reason of 1 to 1000 characters is required")
)

// pendingBlock is a block_override block the user may still override.
type pendingBlock struct {
	ev    events.Event // the blocked event, to derive the overridden one
	uid   string
	sha   string
	limit int
	at    time.Time
}

// overrides holds the grants, the daily counts and the pending blocks.
type overrides struct {
	now func() time.Time

	mu      sync.Mutex
	grants  map[string]time.Time      // uid|channel|sha → until
	daily   map[string]int            // uid|YYYY-MM-DD → overrides
	pending map[string]*pendingBlock  // blocked event id → block
}

func newOverrides() *overrides {
	return &overrides{now: time.Now, grants: map[string]time.Time{}, daily: map[string]int{},
		pending: map[string]*pendingBlock{}}
}

func grantKey(uid, channel, sha string) string {
	return uid + "|" + channel + "|" + strings.ToLower(sha)
}

// allowed reports whether an override lets this file through now.
func (o *overrides) allowed(uid, channel, sha string) bool {
	if o == nil || sha == "" {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	until, ok := o.grants[grantKey(uid, channel, sha)]
	return ok && o.now().Before(until)
}

// remember keeps a blocked event so its user can override it.
func (o *overrides) remember(ev events.Event, uid, sha string, limit int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.now()
	for id, p := range o.pending {
		if now.Sub(p.at) > pendingKeep || len(o.pending) >= maxPendingBlocks {
			delete(o.pending, id)
		}
	}
	o.pending[ev.EventID] = &pendingBlock{ev: ev, uid: uid, sha: sha, limit: limit, at: now}
}

// override grants the blocked event's file to its user with reason and
// returns the overridden event to record. uid must be the blocked event's
// user (the helper that asks is that user's).
func (o *overrides) override(eventID, uid, reason string) (events.Event, error) {
	reason = strings.TrimSpace(reason)
	if n := len([]rune(reason)); n < 1 || n > 1000 {
		return events.Event{}, ErrOverrideReason
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.now()
	p, ok := o.pending[eventID]
	if !ok || p.uid != uid || now.Sub(p.at) > pendingKeep {
		return events.Event{}, ErrOverrideUnknown
	}
	day := uid + "|" + now.Format("2006-01-02")
	if o.daily[day] >= p.limit {
		return events.Event{}, ErrOverrideLimit
	}
	o.daily[day]++
	if len(o.daily) > 4096 {
		today := now.Format("2006-01-02")
		for k := range o.daily {
			if !strings.HasSuffix(k, today) {
				delete(o.daily, k)
			}
		}
	}
	delete(o.pending, eventID)
	if len(o.grants) >= maxOverrideGrants {
		for k, until := range o.grants {
			if !now.Before(until) {
				delete(o.grants, k)
			}
		}
	}
	o.grants[grantKey(uid, p.ev.Channel, p.sha)] = now.Add(overrideAllowFor)

	ev := p.ev
	ev.EventID = events.NewID()
	ev.OccurredAt = now
	ev.Action = events.ActionOverridden
	ev.WouldHave = ""
	ev.UserNotified = nil
	ev.Override = &events.Override{Justification: reason}
	return ev, nil
}

// pendingFor returns a pending block's event (for an exception request).
func (o *overrides) pendingFor(eventID, uid string) (pendingBlock, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	p, ok := o.pending[eventID]
	if !ok || p.uid != uid || o.now().Sub(p.at) > pendingKeep {
		return pendingBlock{}, false
	}
	return *p, true
}
