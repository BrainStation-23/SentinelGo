package adminpassword

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"sentinelgo/internal/supabase"
)

// TickInterval is how often the scheduler polls the policy (§1).
const TickInterval = 15 * time.Minute

// retryDelay is how long the agent waits after a failed rotation.
const retryDelay = time.Hour

// clockSlack absorbs the password-last-set time's one-second granularity
// when settling a pending rotation.
const clockSlack = 2 * time.Second

// StateUnavailable is the task result's state when the server doesn't offer
// the RPCs yet (no status is sent then).
const StateUnavailable = "unavailable"

// Server is the backend: the three RPCs of the contract.
type Server interface {
	FetchPolicy(ctx context.Context, knownVersion string, status *Status) (PolicyResponse, error)
	Escrow(ctx context.Context, e Escrow) error
	Confirm(ctx context.Context, c Confirm) error
}

// Retrier runs one server call, recovering an expired session once
// (auth.Service.DoWithAuthRetry in production).
type Retrier func(ctx context.Context, fn func() error) error

// Options configure a Rotator.
type Options struct {
	Server Server
	Host   Host
	Retry  Retrier // nil calls fn directly
	// StatePath is the state file (StateFileName in the config directory).
	StatePath string
	// LocallyDisabled is the config kill switch
	// (admin_password_rotation_enabled: false).
	LocallyDisabled bool
	Now             func() time.Time
	Logf            func(format string, args ...any)
}

// Rotator runs the rotation loop. Tick and RotateNow are serialized.
type Rotator struct {
	o Options

	mu          sync.Mutex
	state       State
	loaded      bool
	policy      Policy
	known       bool
	rotateAfter *time.Time
	status      Status
	evaluated   bool // status holds a real evaluation (else p_status is null)
	unavailable bool // the server answered 404: no RPCs yet
}

// New returns a Rotator.
func New(o Options) *Rotator {
	if o.Retry == nil {
		o.Retry = func(_ context.Context, fn func() error) error { return fn() }
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logf == nil {
		o.Logf = log.Printf
	}
	return &Rotator{o: o, status: Status{SchemaVersion: 1, State: StateActive}}
}

// Tick is the scheduler task: poll, then rotate if due.
func (r *Rotator) Tick(ctx context.Context) error {
	_, err := r.run(ctx)
	return err
}

// RotateNow is the admin-password-rotate task: the same as a tick, with its
// outcome as the result.
func (r *Rotator) RotateNow(ctx context.Context) (TaskResult, error) {
	return r.run(ctx)
}

// Status returns the last status (for tests and the CLI).
func (r *Rotator) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

func (r *Rotator) run(ctx context.Context) (TaskResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.loaded {
		st, err := loadState(r.o.StatePath)
		if err != nil {
			// A corrupt state file must not stop rotations for good; the
			// server settles any lost pending rotation (§3).
			r.o.Logf("Admin password: state file unreadable, starting fresh: %v", err)
		}
		r.state, r.loaded = st, true
	}
	if err := r.poll(ctx); err != nil {
		return TaskResult{State: StateError}, err
	}
	if r.unavailable {
		return TaskResult{State: StateUnavailable}, nil
	}
	res := r.evaluate(ctx)
	return res, nil
}

// poll fetches the policy and reports the last status.
func (r *Rotator) poll(ctx context.Context) error {
	r.fillStatus()
	var status *Status
	if r.evaluated {
		s := r.status
		status = &s
	}
	var resp PolicyResponse
	err := r.o.Retry(ctx, func() error {
		var err error
		resp, err = r.o.Server.FetchPolicy(ctx, r.knownVersion(), status)
		return err
	})
	if e, ok := supabase.AsAPIError(err); ok && e.Code == SQLStateInvalid && status != nil {
		// A status the server rejects mustn't block the policy.
		r.o.Logf("Admin password: server rejected the status (%v); polling without it", err)
		err = r.o.Retry(ctx, func() error {
			var err error
			resp, err = r.o.Server.FetchPolicy(ctx, r.knownVersion(), nil)
			return err
		})
	}
	switch {
	case err == nil:
	case supabase.IsNotFound(err):
		if !r.unavailable {
			r.o.Logf("Admin password: the server has no %s yet; rotation stays idle", RPCGetPolicy)
		}
		r.unavailable = true
		return nil
	default:
		return fmt.Errorf("%s: %w", RPCGetPolicy, err)
	}
	r.unavailable = false
	if resp.Changed {
		r.policy, r.known = resp.Policy, true
	}
	r.rotateAfter = resp.RotateAfter
	return nil
}

func (r *Rotator) knownVersion() string {
	if !r.known {
		return ""
	}
	return r.policy.Version
}

// evaluate applies the policy: stand down, settle a pending rotation, or
// rotate when due. Failures land in the status, not in the error: the
// server learns about them on the next poll.
func (r *Rotator) evaluate(ctx context.Context) TaskResult {
	r.status.ManagedBy = nil
	if !r.known {
		return TaskResult{State: r.status.State}
	}
	r.evaluated = true
	// A rotation left pending is settled whatever the policy says now: it
	// isn't a rotation, and the server must not keep an unconfirmed
	// password forever.
	settled := true
	if r.state.Pending != nil && r.o.Host.Unsupported() == "" {
		settled = r.settle(ctx)
	}
	if r.o.LocallyDisabled || !r.policy.Enabled {
		r.status.State = StateDisabled
		return TaskResult{State: StateDisabled}
	}
	if reason := r.o.Host.Unsupported(); reason != "" {
		r.status.State = StateUnsupported
		return TaskResult{State: StateUnsupported}
	}
	by, err := r.o.Host.ManagedBy()
	if err != nil {
		// Unknown means don't touch it: two rotators would fight.
		r.o.Logf("Admin password: couldn't check for Windows LAPS, not rotating: %v", err)
		r.status.State = StateError
		return TaskResult{State: StateError}
	}
	if by != "" {
		r.status.State = StateManagedElsewhere
		r.status.ManagedBy = &by
		return TaskResult{State: StateManagedElsewhere}
	}

	acct, err := r.o.Host.Account(r.policy.Account.Name)
	if err != nil {
		code := ErrCodeAccountLookup
		if errors.Is(err, ErrAccountNotFound) {
			code = ErrCodeAccountNotFound
		}
		r.o.Logf("Admin password: target account: %v", err)
		r.fail(code, false)
		r.status.Account = nil
		return TaskResult{State: StateError, ErrorCode: code}
	}
	r.status.Account = &StatusAccount{Name: acct.Name, SID: acct.SID, Builtin: acct.Builtin, Enabled: acct.Enabled}

	if !settled || r.state.Pending != nil {
		// Never start a rotation while the last one is unsettled.
		r.status.State = StateError
		return TaskResult{State: StateError, ErrorCode: ErrCodeConfirmFailed}
	}

	now := r.o.Now()
	reason := r.due(acct, now)
	if reason == "" {
		r.status.State = StateActive
		if r.state.LastError != nil && (r.state.RetryAfter == nil || !now.Before(*r.state.RetryAfter)) {
			r.state.LastError, r.state.RetryAfter = nil, nil
			r.save()
		}
		return TaskResult{State: StateActive}
	}
	if r.state.RetryAfter != nil && now.Before(*r.state.RetryAfter) {
		r.status.State = StateError
		return TaskResult{State: StateError, ErrorCode: r.lastCode()}
	}
	return r.rotate(ctx, acct, reason)
}

// due returns why a rotation is due now, or "" (§ Agent behaviour 4).
func (r *Rotator) due(acct AccountInfo, now time.Time) string {
	st := r.state
	if st.LastRotationID == "" || st.LastRotatedAt == nil {
		return ReasonInitial
	}
	last := *st.LastRotatedAt
	switch {
	case st.AccountSID != "" && st.AccountSID != acct.SID:
		return ReasonAccountChanged
	case r.rotateAfter != nil && last.Before(*r.rotateAfter) && !now.Before(*r.rotateAfter):
		return ReasonRequested
	case acct.LastLogon.After(last) && !now.Before(acct.LastLogon.Add(r.policy.PostUseDelay())):
		return ReasonPostUse
	case !now.Before(last.Add(r.policy.RotateEvery())):
		return ReasonScheduled
	}
	return ""
}

// nextRotation is the earliest time a rotation becomes due.
func (r *Rotator) nextRotation() *time.Time {
	st := r.state
	if !r.known || st.LastRotatedAt == nil {
		return nil
	}
	last := *st.LastRotatedAt
	next := last.Add(r.policy.RotateEvery())
	if r.rotateAfter != nil && last.Before(*r.rotateAfter) && r.rotateAfter.Before(next) {
		next = *r.rotateAfter
	}
	return &next
}

// rotate escrows a new password, then sets it, then confirms (§2–3). If
// the escrow fails, the device's password is left as it is.
func (r *Rotator) rotate(ctx context.Context, acct AccountInfo, reason string) TaskResult {
	pw, err := Generate(r.policy.Password.Length, r.policy.Password.Complexity)
	if err != nil {
		r.o.Logf("Admin password: generate: %v", err)
		r.fail(ErrCodeSetFailed, true)
		return TaskResult{State: StateError, ErrorCode: ErrCodeSetFailed}
	}
	defer zero(pw)
	id, err := newRotationID()
	if err != nil {
		r.o.Logf("Admin password: %v", err)
		r.fail(ErrCodeSetFailed, true)
		return TaskResult{State: StateError, ErrorCode: ErrCodeSetFailed}
	}
	esc := Escrow{
		RotationID:  id,
		AccountName: acct.Name,
		AccountSID:  acct.SID,
		Password:    string(pw),
		Reason:      reason,
		GeneratedAt: r.o.Now().UTC(),
	}
	err = r.o.Retry(ctx, func() error { return r.o.Server.Escrow(ctx, esc) })
	esc.Password = ""
	if err != nil {
		r.o.Logf("Admin password: escrow of rotation %s failed, password unchanged: %v", id, err)
		r.fail(ErrCodeEscrowFailed, true)
		return TaskResult{State: StateError, ErrorCode: ErrCodeEscrowFailed, RotationID: id}
	}

	r.state.Pending = &Pending{RotationID: id, AccountSID: acct.SID, Reason: reason, StartedAt: r.o.Now().UTC()}
	if err := saveState(r.o.StatePath, r.state); err != nil {
		// Without a saved pending rotation a crash couldn't be settled:
		// don't change the password.
		r.o.Logf("Admin password: save state, password unchanged: %v", err)
		r.state.Pending = nil
		r.confirmFailed(ctx, id, ErrCodeSetFailed)
		r.fail(ErrCodeSetFailed, true)
		return TaskResult{State: StateError, ErrorCode: ErrCodeSetFailed, RotationID: id}
	}

	if err := r.o.Host.SetPassword(acct, pw); err != nil {
		code := ErrCodeSetFailed
		if errors.Is(err, ErrPasswordPolicy) {
			code = ErrCodePasswordPolicy
		}
		r.o.Logf("Admin password: set password for rotation %s failed (%s): %v", id, code, err)
		if r.confirmFailed(ctx, id, code) {
			r.state.Pending = nil
		}
		r.fail(code, true)
		return TaskResult{State: StateError, ErrorCode: code, RotationID: id}
	}

	applied := r.o.Now().UTC()
	if err := r.confirm(ctx, Confirm{RotationID: id, State: ConfirmApplied, AppliedAt: &applied}); err != nil {
		// The pending rotation stays; the next tick settles it.
		r.o.Logf("Admin password: rotation %s applied, confirm failed (retried next tick): %v", id, err)
		r.fail(ErrCodeConfirmFailed, false)
		return TaskResult{State: StateError, Rotated: true, ErrorCode: ErrCodeConfirmFailed, RotationID: id}
	}
	r.applied(id, acct.SID, applied)
	r.o.Logf("Admin password: rotated %s (%s), rotation %s", acct.Name, reason, id)
	r.status.State = StateActive
	return TaskResult{State: StateActive, Rotated: true, RotationID: id}
}

// settle confirms a pending rotation left by a crash or a failed confirm:
// applied if the password changed after the rotation started, failed
// otherwise. It returns false when the server couldn't be told.
func (r *Rotator) settle(ctx context.Context) bool {
	p := r.state.Pending
	acct, err := r.o.Host.AccountBySID(p.AccountSID)
	switch {
	case errors.Is(err, ErrAccountNotFound):
		// The account is gone: whatever was set on it no longer matters.
		acct = AccountInfo{SID: p.AccountSID}
	case err != nil:
		// Can't tell whether it was applied: keep it pending and ask again.
		r.o.Logf("Admin password: settle rotation %s: look up the account: %v", p.RotationID, err)
		return false
	}
	applied := !acct.PasswordLastSet.IsZero() && !acct.PasswordLastSet.Before(p.StartedAt.Add(-clockSlack))
	var c Confirm
	if applied {
		at := acct.PasswordLastSet.UTC()
		c = Confirm{RotationID: p.RotationID, State: ConfirmApplied, AppliedAt: &at}
	} else {
		c = Confirm{RotationID: p.RotationID, State: ConfirmFailed, ErrorCode: ErrCodeNotApplied}
	}
	err = r.confirm(ctx, c)
	switch {
	case err == nil:
	case isUnknownRotation(err):
		r.o.Logf("Admin password: server doesn't know pending rotation %s; dropping it", p.RotationID)
		r.state.Pending = nil
		r.save()
		return true
	default:
		r.o.Logf("Admin password: settle rotation %s: %v", p.RotationID, err)
		r.fail(ErrCodeConfirmFailed, false)
		return false
	}
	if applied {
		r.applied(p.RotationID, p.AccountSID, *c.AppliedAt)
		r.o.Logf("Admin password: pending rotation %s confirmed as applied", p.RotationID)
	} else {
		r.state.Pending = nil
		r.save()
		r.o.Logf("Admin password: pending rotation %s was not applied; reported", p.RotationID)
	}
	return true
}

func (r *Rotator) confirm(ctx context.Context, c Confirm) error {
	return r.o.Retry(ctx, func() error { return r.o.Server.Confirm(ctx, c) })
}

// confirmFailed tells the server a rotation wasn't applied; true when it
// knows (or never knew) the rotation.
func (r *Rotator) confirmFailed(ctx context.Context, id, code string) bool {
	err := r.confirm(ctx, Confirm{RotationID: id, State: ConfirmFailed, ErrorCode: code})
	if err == nil || isUnknownRotation(err) {
		return true
	}
	r.o.Logf("Admin password: report failed rotation %s: %v", id, err)
	return false
}

func isUnknownRotation(err error) bool {
	e, ok := supabase.AsAPIError(err)
	return ok && e.Code == SQLStateNotFound
}

// applied records a confirmed rotation.
func (r *Rotator) applied(id, sid string, at time.Time) {
	r.state.LastRotationID = id
	r.state.LastRotatedAt = &at
	r.state.AccountSID = sid
	r.state.Pending = nil
	r.state.LastError = nil
	r.state.RetryAfter = nil
	r.save()
}

// fail records a failure; backoff delays the next attempt.
func (r *Rotator) fail(code string, backoff bool) {
	now := r.o.Now().UTC()
	r.state.LastError = &StatusError{Code: code, At: now}
	if backoff {
		t := now.Add(retryDelay)
		r.state.RetryAfter = &t
	}
	r.status.State = StateError
	r.save()
}

func (r *Rotator) lastCode() string {
	if r.state.LastError == nil {
		return ""
	}
	return r.state.LastError.Code
}

func (r *Rotator) save() {
	if err := saveState(r.o.StatePath, r.state); err != nil {
		r.o.Logf("Admin password: save state: %v", err)
	}
}

// fillStatus copies the persisted state into the status the next poll
// reports.
func (r *Rotator) fillStatus() {
	st := r.state
	r.status.SchemaVersion = 1
	r.status.LastRotationID = st.LastRotationID
	r.status.LastRotatedAt = st.LastRotatedAt
	r.status.NextRotationAt = r.nextRotation()
	r.status.PendingRotationID = nil
	if st.Pending != nil {
		id := st.Pending.RotationID
		r.status.PendingRotationID = &id
	}
	r.status.LastError = st.LastError
	r.status.PolicyVersion = r.knownVersion()
}
