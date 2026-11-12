package adminpassword

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/supabase"
)

// fakeServer records calls and answers like the backend.
type fakeServer struct {
	mu          sync.Mutex
	policy      Policy
	rotateAfter *time.Time
	fetchErr    error
	escrowErr   error
	confirmErr  error
	statuses    []*Status
	escrows     []Escrow
	confirms    []Confirm
	events      *[]string
}

func (s *fakeServer) FetchPolicy(_ context.Context, known string, st *Status) (PolicyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st != nil {
		c := *st
		s.statuses = append(s.statuses, &c)
	} else {
		s.statuses = append(s.statuses, nil)
	}
	if s.fetchErr != nil {
		return PolicyResponse{}, s.fetchErr
	}
	resp := PolicyResponse{RotateAfter: s.rotateAfter}
	if known != s.policy.Version {
		resp.Changed, resp.Policy = true, normalize(s.policy)
	}
	return resp, nil
}

func (s *fakeServer) Escrow(_ context.Context, e Escrow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log("escrow")
	if s.escrowErr != nil {
		return s.escrowErr
	}
	s.escrows = append(s.escrows, e)
	return nil
}

func (s *fakeServer) Confirm(_ context.Context, c Confirm) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log("confirm:" + c.State)
	if s.confirmErr != nil {
		return s.confirmErr
	}
	s.confirms = append(s.confirms, c)
	return nil
}

func (s *fakeServer) log(e string) {
	if s.events != nil {
		*s.events = append(*s.events, e)
	}
}

// fakeHost is one Windows device with a password and a logon history.
type fakeHost struct {
	acct        AccountInfo
	other       map[string]AccountInfo
	unsupported string
	managedBy   string
	managedErr  error
	acctErr     error
	setErr      error
	password    string
	sets        int
	now         func() time.Time
	events      *[]string
}

func (h *fakeHost) Unsupported() string        { return h.unsupported }
func (h *fakeHost) ManagedBy() (string, error) { return h.managedBy, h.managedErr }
func (h *fakeHost) Account(string) (AccountInfo, error) {
	if h.acctErr != nil {
		return AccountInfo{}, h.acctErr
	}
	return h.acct, nil
}
func (h *fakeHost) AccountBySID(sid string) (AccountInfo, error) {
	if sid == h.acct.SID {
		return h.acct, nil
	}
	if a, ok := h.other[sid]; ok {
		return a, nil
	}
	return AccountInfo{}, ErrAccountNotFound
}
func (h *fakeHost) SetPassword(_ AccountInfo, pw []byte) error {
	if h.events != nil {
		*h.events = append(*h.events, "set")
	}
	if h.setErr != nil {
		return h.setErr
	}
	h.sets++
	h.password = string(pw)
	h.acct.PasswordLastSet = h.now().Truncate(time.Second)
	return nil
}

type harness struct {
	t      *testing.T
	now    time.Time
	server *fakeServer
	host   *fakeHost
	logs   []string
	events []string
	path   string
	r      *Rotator
}

var t0 = time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, now: t0, path: filepath.Join(t.TempDir(), StateFileName)}
	h.server = &fakeServer{
		policy: Policy{Version: "v1", Enabled: true, Password: PasswordRules{Length: 24, Complexity: 4}, RotateEveryDays: 30},
		events: &h.events,
	}
	h.host = &fakeHost{
		acct:   AccountInfo{Name: "Administrator", SID: "S-1-5-21-1-2-3-500", Builtin: true, PasswordLastSet: t0.Add(-400 * 24 * time.Hour)},
		now:    func() time.Time { return h.now },
		events: &h.events,
	}
	h.r = h.rotator(false)
	return h
}

func (h *harness) rotator(disabled bool) *Rotator {
	return New(Options{
		Server: h.server, Host: h.host, StatePath: h.path, LocallyDisabled: disabled,
		Now:  func() time.Time { return h.now },
		Logf: func(f string, a ...any) { h.logs = append(h.logs, fmt.Sprintf(f, a...)) },
	})
}

func (h *harness) tick() TaskResult {
	h.t.Helper()
	res, err := h.r.RotateNow(context.Background())
	if err != nil {
		h.t.Fatalf("tick: %v", err)
	}
	return res
}

// noSecretAnywhere checks that no generated password reached a log, a
// status, the state file or a task result.
func (h *harness) noSecretAnywhere(results ...TaskResult) {
	h.t.Helper()
	var secrets []string
	for _, e := range h.server.escrows {
		secrets = append(secrets, e.Password)
	}
	if h.host.password != "" {
		secrets = append(secrets, h.host.password)
	}
	state, _ := os.ReadFile(h.path)
	haystack := []string{strings.Join(h.logs, "\n"), string(state)}
	for _, st := range h.server.statuses {
		if st != nil {
			data, _ := st.Encode()
			haystack = append(haystack, string(data))
		}
	}
	for _, r := range results {
		haystack = append(haystack, fmt.Sprintf("%+v", r))
	}
	for _, s := range secrets {
		for _, hay := range haystack {
			if s != "" && strings.Contains(hay, s) {
				h.t.Fatalf("password leaked into %q", hay)
			}
		}
	}
}

func TestRotator_InitialRotationEscrowsBeforeSetting(t *testing.T) {
	h := newHarness(t)
	res := h.tick()
	if !res.Rotated || res.State != StateActive || res.ErrorCode != "" {
		t.Fatalf("result %+v", res)
	}
	if got := strings.Join(h.events, ","); got != "escrow,set,confirm:applied" {
		t.Fatalf("order = %s", got)
	}
	e := h.server.escrows[0]
	if e.Reason != ReasonInitial || e.AccountSID != h.host.acct.SID || e.Password != h.host.password || len(e.Password) != 24 {
		t.Fatalf("escrow %v (len %d)", e, len(e.Password))
	}
	c := h.server.confirms[0]
	if c.RotationID != e.RotationID || c.State != ConfirmApplied || c.AppliedAt == nil {
		t.Fatalf("confirm %+v", c)
	}
	st, err := loadState(h.path)
	if err != nil || st.LastRotationID != e.RotationID || st.Pending != nil || st.AccountSID != h.host.acct.SID {
		t.Fatalf("state %+v, %v", st, err)
	}
	// The first poll had no status; the next one reports the rotation.
	if h.server.statuses[0] != nil {
		t.Fatal("first poll sent a status before any evaluation")
	}
	h.now = h.now.Add(time.Minute)
	if res := h.tick(); res.Rotated {
		t.Fatalf("rotated again: %+v", res)
	}
	last := h.server.statuses[len(h.server.statuses)-1]
	if last == nil || last.State != StateActive || last.LastRotationID != e.RotationID || last.Account == nil || !last.Account.Builtin {
		t.Fatalf("status %+v", last)
	}
	if want := t0.Add(30 * 24 * time.Hour); last.NextRotationAt == nil || !last.NextRotationAt.Equal(want) {
		t.Fatalf("next rotation %v, want %v", last.NextRotationAt, want)
	}
	h.noSecretAnywhere(res)
}

func TestRotator_EscrowFailureLeavesPasswordUnchanged(t *testing.T) {
	h := newHarness(t)
	h.server.escrowErr = errors.New("connection reset")
	res := h.tick()
	if res.Rotated || res.ErrorCode != ErrCodeEscrowFailed {
		t.Fatalf("result %+v", res)
	}
	if h.host.sets != 0 {
		t.Fatal("password set although the escrow failed")
	}
	// Backoff: an hour later, not before.
	h.server.escrowErr = nil
	h.now = h.now.Add(30 * time.Minute)
	if res := h.tick(); res.Rotated {
		t.Fatal("retried inside the backoff")
	}
	h.now = h.now.Add(31 * time.Minute)
	if res := h.tick(); !res.Rotated {
		t.Fatalf("not retried after the backoff: %+v", res)
	}
	h.noSecretAnywhere()
}

func TestRotator_OfflineNeverRotates(t *testing.T) {
	h := newHarness(t)
	h.server.fetchErr = errors.New("dial tcp: no route to host")
	if _, err := h.r.RotateNow(context.Background()); err == nil {
		t.Fatal("offline poll returned no error")
	}
	if h.host.sets != 0 || len(h.server.escrows) != 0 {
		t.Fatal("rotated while offline")
	}
}

func TestRotator_SetFailureReportsPolicyError(t *testing.T) {
	h := newHarness(t)
	h.host.setErr = fmt.Errorf("%w (NET 2245)", ErrPasswordPolicy)
	res := h.tick()
	if res.ErrorCode != ErrCodePasswordPolicy || res.Rotated {
		t.Fatalf("result %+v", res)
	}
	c := h.server.confirms[0]
	if c.State != ConfirmFailed || c.ErrorCode != ErrCodePasswordPolicy || c.RotationID != h.server.escrows[0].RotationID {
		t.Fatalf("confirm %+v", c)
	}
	st, _ := loadState(h.path)
	if st.Pending != nil || st.LastError == nil || st.LastError.Code != ErrCodePasswordPolicy {
		t.Fatalf("state %+v", st)
	}
}

func TestRotator_ConfirmFailureSettledNextTick(t *testing.T) {
	h := newHarness(t)
	h.server.confirmErr = errors.New("503")
	res := h.tick()
	if !res.Rotated || res.ErrorCode != ErrCodeConfirmFailed {
		t.Fatalf("result %+v", res)
	}
	st, _ := loadState(h.path)
	if st.Pending == nil {
		t.Fatal("pending rotation not kept")
	}
	h.server.confirmErr = nil
	h.now = h.now.Add(15 * time.Minute)
	h.tick()
	if len(h.server.confirms) != 1 || h.server.confirms[0].State != ConfirmApplied {
		t.Fatalf("confirms %+v", h.server.confirms)
	}
	if h.host.sets != 1 || len(h.server.escrows) != 1 {
		t.Fatal("rotated again instead of settling")
	}
	st, _ = loadState(h.path)
	if st.Pending != nil || st.LastRotationID != h.server.escrows[0].RotationID {
		t.Fatalf("state %+v", st)
	}
}

// A crash between the escrow and the set: the password didn't change, so
// the restarted agent reports not_applied and then rotates afresh.
func TestRotator_CrashBeforeSetIsNotApplied(t *testing.T) {
	h := newHarness(t)
	started := t0.Add(-time.Minute)
	if err := saveState(h.path, State{Pending: &Pending{RotationID: "old", AccountSID: h.host.acct.SID, Reason: ReasonInitial, StartedAt: started}}); err != nil {
		t.Fatal(err)
	}
	h.tick()
	if len(h.server.confirms) < 1 || h.server.confirms[0] != (Confirm{RotationID: "old", State: ConfirmFailed, ErrorCode: ErrCodeNotApplied}) {
		t.Fatalf("confirms %+v", h.server.confirms)
	}
	if h.host.sets != 1 {
		t.Fatal("didn't rotate after settling")
	}
}

// A crash after the set: the password changed after the rotation started,
// so the restarted agent confirms it as applied, and doesn't rotate again.
func TestRotator_CrashAfterSetIsApplied(t *testing.T) {
	h := newHarness(t)
	started := t0.Add(-time.Minute)
	h.host.acct.PasswordLastSet = started.Add(time.Second)
	if err := saveState(h.path, State{Pending: &Pending{RotationID: "old", AccountSID: h.host.acct.SID, Reason: ReasonInitial, StartedAt: started}}); err != nil {
		t.Fatal(err)
	}
	res := h.tick()
	if len(h.server.confirms) != 1 || h.server.confirms[0].State != ConfirmApplied || h.server.confirms[0].RotationID != "old" {
		t.Fatalf("confirms %+v", h.server.confirms)
	}
	if res.Rotated || h.host.sets != 0 {
		t.Fatal("rotated again after settling an applied rotation")
	}
	st, _ := loadState(h.path)
	if st.LastRotationID != "old" || st.Pending != nil {
		t.Fatalf("state %+v", st)
	}
}

func TestRotator_UnknownPendingDropped(t *testing.T) {
	h := newHarness(t)
	_ = saveState(h.path, State{LastRotationID: "x", LastRotatedAt: &t0, AccountSID: h.host.acct.SID,
		Pending: &Pending{RotationID: "lost", AccountSID: h.host.acct.SID, StartedAt: t0}})
	h.server.confirmErr = &supabase.APIError{Status: 404, Code: SQLStateNotFound}
	h.tick()
	st, _ := loadState(h.path)
	if st.Pending != nil {
		t.Fatalf("unknown pending kept: %+v", st)
	}
}

func TestRotator_DueReasons(t *testing.T) {
	cases := []struct {
		name  string
		setup func(h *harness)
		want  string
	}{
		{"scheduled", func(h *harness) { h.now = h.now.Add(30 * 24 * time.Hour) }, ReasonScheduled},
		{"not yet", func(h *harness) { h.now = h.now.Add(29 * 24 * time.Hour) }, ""},
		{"requested", func(h *harness) {
			ra := h.now.Add(time.Hour)
			h.server.rotateAfter = &ra
			h.now = h.now.Add(2 * time.Hour)
		}, ReasonRequested},
		{"requested in the future", func(h *harness) {
			ra := h.now.Add(3 * time.Hour)
			h.server.rotateAfter = &ra
			h.now = h.now.Add(2 * time.Hour)
		}, ""},
		{"request older than the last rotation", func(h *harness) {
			ra := t0.Add(-time.Hour)
			h.server.rotateAfter = &ra
			h.now = h.now.Add(2 * time.Hour)
		}, ""},
		{"post use", func(h *harness) {
			h.host.acct.LastLogon = h.now.Add(time.Hour)
			h.now = h.now.Add(9 * time.Hour)
		}, ReasonPostUse},
		{"post use inside the delay", func(h *harness) {
			h.host.acct.LastLogon = h.now.Add(time.Hour)
			h.now = h.now.Add(5 * time.Hour)
		}, ""},
		{"account changed", func(h *harness) {
			h.host.acct.SID = "S-1-5-21-1-2-3-1001"
			h.host.acct.Name, h.host.acct.Builtin = "LocalAdm", false
			h.now = h.now.Add(time.Hour)
		}, ReasonAccountChanged},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.tick() // initial rotation at t0
			c.setup(h)
			res := h.tick()
			got := ""
			if res.Rotated {
				got = h.server.escrows[len(h.server.escrows)-1].Reason
			}
			if got != c.want {
				t.Fatalf("reason %q, want %q (result %+v)", got, c.want, res)
			}
		})
	}
}

func TestRotator_StandsDown(t *testing.T) {
	cases := []struct {
		name      string
		setup     func(h *harness)
		disabled  bool
		state     string
		managedBy string
	}{
		{"policy disabled", func(h *harness) { h.server.policy.Enabled = false }, false, StateDisabled, ""},
		{"kill switch", func(*harness) {}, true, StateDisabled, ""},
		{"domain controller", func(h *harness) { h.host.unsupported = "domain_controller" }, false, StateUnsupported, ""},
		{"windows LAPS", func(h *harness) { h.host.managedBy = ManagedByWindowsLAPS }, false, StateManagedElsewhere, ManagedByWindowsLAPS},
		{"legacy LAPS", func(h *harness) { h.host.managedBy = ManagedByLegacyLAPS }, false, StateManagedElsewhere, ManagedByLegacyLAPS},
		{"LAPS state unknown", func(h *harness) { h.host.managedErr = errors.New("access denied") }, false, StateError, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			c.setup(h)
			h.r = h.rotator(c.disabled)
			res := h.tick()
			h.tick()
			if res.Rotated || h.host.sets != 0 || len(h.server.escrows) != 0 {
				t.Fatal("rotated while standing down")
			}
			st := h.server.statuses[len(h.server.statuses)-1]
			if st == nil || st.State != c.state {
				t.Fatalf("status %+v, want state %s", st, c.state)
			}
			got := ""
			if st.ManagedBy != nil {
				got = *st.ManagedBy
			}
			if got != c.managedBy {
				t.Fatalf("managed_by %q, want %q", got, c.managedBy)
			}
		})
	}
}

func TestRotator_AccountNotFound(t *testing.T) {
	h := newHarness(t)
	h.host.acctErr = fmt.Errorf("%w: LocalAdm", ErrAccountNotFound)
	res := h.tick()
	if res.ErrorCode != ErrCodeAccountNotFound || h.host.sets != 0 || len(h.server.escrows) != 0 {
		t.Fatalf("result %+v", res)
	}
	h.tick()
	st := h.server.statuses[len(h.server.statuses)-1]
	if st.State != StateError || st.LastError == nil || st.LastError.Code != ErrCodeAccountNotFound || st.Account != nil {
		t.Fatalf("status %+v", st)
	}
	// Once the account exists, the error clears with the rotation.
	h.host.acctErr = nil
	if res := h.tick(); !res.Rotated {
		t.Fatalf("not rotated once the account exists: %+v", res)
	}
	h.tick()
	if st := h.server.statuses[len(h.server.statuses)-1]; st.LastError != nil || st.State != StateActive {
		t.Fatalf("status %+v", st)
	}
}

func TestRotator_ServerWithoutRPCsStaysIdle(t *testing.T) {
	h := newHarness(t)
	h.server.fetchErr = &supabase.APIError{Status: 404, Code: "PGRST202"}
	res := h.tick()
	h.tick()
	if res.State != StateUnavailable || h.host.sets != 0 {
		t.Fatalf("result %+v", res)
	}
	n := 0
	for _, l := range h.logs {
		if strings.Contains(l, "no "+RPCGetPolicy) {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("logged the missing RPC %d times, want once", n)
	}
}

// A status the server rejects (22023) mustn't stop the policy poll.
type rejectingServer struct {
	*fakeServer
	calls int
}

func (s *rejectingServer) FetchPolicy(ctx context.Context, known string, st *Status) (PolicyResponse, error) {
	s.calls++
	if st != nil {
		return PolicyResponse{}, &supabase.APIError{Status: 400, Code: SQLStateInvalid}
	}
	return s.fakeServer.FetchPolicy(ctx, known, nil)
}

func TestRotator_RejectedStatusRetriedWithout(t *testing.T) {
	h := newHarness(t)
	rs := &rejectingServer{fakeServer: h.server}
	r := New(Options{Server: rs, Host: h.host, StatePath: h.path, Now: func() time.Time { return h.now }, Logf: func(string, ...any) {}})
	ctx := context.Background()
	if _, err := r.RotateNow(ctx); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(time.Minute)
	if _, err := r.RotateNow(ctx); err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if rs.calls != 3 {
		t.Fatalf("FetchPolicy calls = %d, want 3 (null, rejected, retried)", rs.calls)
	}
}

func TestRotator_CorruptStateStartsFresh(t *testing.T) {
	h := newHarness(t)
	if err := os.WriteFile(h.path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := h.tick(); !res.Rotated {
		t.Fatalf("result %+v", res)
	}
}

// The kill switch and the rotation run are serialized: concurrent ticks
// never escrow twice for one due rotation.
func TestRotator_ConcurrentTicks(t *testing.T) {
	h := newHarness(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = h.r.Tick(context.Background())
		}()
	}
	wg.Wait()
	if len(h.server.escrows) != 1 || h.host.sets != 1 {
		t.Fatalf("escrows %d, sets %d", len(h.server.escrows), h.host.sets)
	}
}

// A pending rotation is settled even after the policy was turned off.
func TestRotator_SettlesPendingWhenDisabled(t *testing.T) {
	h := newHarness(t)
	h.server.policy.Enabled = false
	if err := saveState(h.path, State{Pending: &Pending{RotationID: "old", AccountSID: h.host.acct.SID, StartedAt: t0.Add(-time.Minute)}}); err != nil {
		t.Fatal(err)
	}
	res := h.tick()
	if res.State != StateDisabled || h.host.sets != 0 {
		t.Fatalf("result %+v", res)
	}
	if len(h.server.confirms) != 1 || h.server.confirms[0].ErrorCode != ErrCodeNotApplied {
		t.Fatalf("confirms %+v", h.server.confirms)
	}
	if st, _ := loadState(h.path); st.Pending != nil {
		t.Fatalf("pending kept: %+v", st)
	}
}

// A pending rotation whose account was renamed or replaced is settled
// against the account it was escrowed for, not the current target.
func TestRotator_SettlesPendingByItsOwnAccount(t *testing.T) {
	h := newHarness(t)
	old := AccountInfo{Name: "OldAdm", SID: "S-1-5-21-1-2-3-1001", PasswordLastSet: t0}
	h.host.other = map[string]AccountInfo{old.SID: old}
	if err := saveState(h.path, State{Pending: &Pending{RotationID: "old", AccountSID: old.SID, StartedAt: t0.Add(-time.Minute)}}); err != nil {
		t.Fatal(err)
	}
	h.tick()
	if len(h.server.confirms) < 1 || h.server.confirms[0].State != ConfirmApplied || h.server.confirms[0].RotationID != "old" {
		t.Fatalf("confirms %+v", h.server.confirms)
	}
	// The target is a different account, so it's rotated next.
	if len(h.server.escrows) != 1 || h.server.escrows[0].Reason != ReasonAccountChanged {
		t.Fatalf("escrows %v", h.server.escrows)
	}
}
