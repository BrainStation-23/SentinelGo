package mdmenroll

import (
	"context"
	"fmt"
	"sync"
	"time"

	"sentinelgo/internal/osinfo/mdm"
	"sentinelgo/internal/osinfo/shared"
)

// Sync outcome codes (mdm-sync, #357).
const (
	ResultSynced      = "synced"
	ResultCoalesced   = "coalesced"
	ResultNotEnrolled = "not_enrolled"
)

// syncEvery coalesces syncs: a burst of queued commands needs one session.
var syncEvery = 30 * time.Second

// Syncer runs mdm-sync: it starts an MDM session for this deployment's
// enrollment now, so a queued command doesn't wait for the next poll. It
// stands in for push notifications, which Windows MDM would need WNS for.
type Syncer struct {
	OurHost func() string
	Collect func(ourHost string) *shared.MDMInfo
	// Start starts a session for the enrollment with the given ID.
	Start func(ctx context.Context, enrollmentID string) error
	Now   func() time.Time

	mu   sync.Mutex
	last time.Time
}

// NewSyncer returns the platform's syncer.
func NewSyncer(ourHost func() string) *Syncer {
	return &Syncer{OurHost: ourHost, Collect: mdm.Collect, Start: startSession, Now: time.Now}
}

// Sync starts a session for our enrollment, at most once per syncEvery. It
// never touches another MDM's enrollment.
func (s *Syncer) Sync(ctx context.Context, mdmHost string) (Outcome, error) {
	host := mdmHost
	if host == "" && s.OurHost != nil {
		host = s.OurHost()
	}
	if s.Start == nil {
		return Outcome{}, fail(ResultUnsupportedOS, "starting an MDM session isn't supported on this platform")
	}
	info := s.Collect(host)
	if info == nil || info.Eligible == nil {
		return Outcome{}, fail(ResultUnsupportedOS, "starting an MDM session isn't supported on this platform")
	}
	if host == "" {
		return Outcome{}, fail(ResultMDMHostUnknown, "mdm_host isn't set, so the agent can't tell which enrollment is this deployment's")
	}
	var id string
	for _, e := range info.Enrollments {
		if mdm.IsOurServer(e.ServerHost, host) {
			id = e.ID
			break
		}
	}
	if id == "" {
		return Outcome{}, fail(ResultNotEnrolled, "the device isn't enrolled in this deployment's MDM")
	}

	now := s.Now()
	s.mu.Lock()
	if !s.last.IsZero() && now.Sub(s.last) < syncEvery {
		last := s.last
		s.mu.Unlock()
		return Outcome{ResultCoalesced, fmt.Sprintf("a session was started %s ago; it picks up queued commands", now.Sub(last).Round(time.Second))}, nil
	}
	s.last = now
	s.mu.Unlock()

	if err := s.Start(ctx, id); err != nil {
		s.mu.Lock()
		s.last = time.Time{} // let the next attempt through
		s.mu.Unlock()
		return Outcome{}, fmt.Errorf("mdm-sync: starting a session for enrollment %s: %w", id, err)
	}
	return Outcome{ResultSynced, "started an MDM session for enrollment " + id}, nil
}
