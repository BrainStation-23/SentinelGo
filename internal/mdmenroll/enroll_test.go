package mdmenroll

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/dlp/ipc"
	"sentinelgo/internal/dlp/session"
	"sentinelgo/internal/osinfo/shared"
)

// fakeDevice drives an Enroller: its MDM state can change after a step
// (e.g. the user approves the profile), and calls are recorded.
type fakeDevice struct {
	info       *shared.MDMInfo
	afterStart *shared.MDMInfo // state once enrollment was started
	started    bool
	console    *Session
	fetches    int
	presented  []ipc.OpenProfile
	presentErr error
	renews     int
	renewErr   error
	clock      time.Time
	sleeps     int
	// active says whether the console user is at the Mac; nil means yes.
	active func() bool
	// fetchedWhileIdle is set when a profile was fetched for an idle user.
	fetchedWhileIdle bool
}

func ptr(b bool) *bool { return &b }

func (f *fakeDevice) deps() Deps {
	return Deps{
		OurHost: func() string { return "mdm.example.com" },
		Collect: func(string) *shared.MDMInfo {
			if f.started && f.afterStart != nil {
				return f.afterStart
			}
			return f.info
		},
		FetchProfile: func(context.Context) ([]byte, error) {
			f.fetches++
			if f.active != nil && !f.active() {
				f.fetchedWhileIdle = true
			}
			return []byte("<?xml p"), nil
		},
		UserActive: func(Session) bool { return f.active == nil || f.active() },
		Present: func(_ context.Context, sid string, p ipc.OpenProfile) error {
			if f.presentErr != nil {
				return f.presentErr
			}
			f.presented = append(f.presented, p)
			f.started = true
			return nil
		},
		ConsoleSession: func() (Session, bool) {
			if f.console == nil {
				return Session{}, false
			}
			return *f.console, true
		},
		RenewADE: func(context.Context) error { f.renews++; f.started = true; return f.renewErr },
		Now:      func() time.Time { return f.clock },
		Sleep: func(ctx context.Context, d time.Duration) error {
			f.sleeps++
			f.clock = f.clock.Add(d)
			return ctx.Err()
		},
	}
}

func notEnrolled(ade *bool, adeHost string) *shared.MDMInfo {
	return &shared.MDMInfo{EnrollmentType: "none", ADEAssigned: ade, ADEServerHost: adeHost}
}

var enrolledOurs = &shared.MDMInfo{Enrolled: true, EnrollmentType: "profile", ServerURLHost: "mdm.example.com", IsOurServer: true}

func outcomeCode(t *testing.T, err error) string {
	t.Helper()
	var oe *OutcomeError
	if !errors.As(err, &oe) {
		t.Fatalf("error %v is not an OutcomeError", err)
	}
	return oe.Code
}

func TestEnroll_AlreadyEnrolledOrOtherMDM(t *testing.T) {
	f := &fakeDevice{info: enrolledOurs}
	out, err := New(f.deps()).Enroll(context.Background(), Request{Method: MethodAuto})
	if err != nil || out.Code != ResultAlreadyEnrolled {
		t.Errorf("ours: %v %v", out, err)
	}

	f = &fakeDevice{info: &shared.MDMInfo{Enrolled: true, ServerURLHost: "mdm.other.com"}}
	_, err = New(f.deps()).Enroll(context.Background(), Request{Method: MethodAuto})
	if code := outcomeCode(t, err); code != ResultOtherMDM || !strings.Contains(err.Error(), "mdm.other.com") {
		t.Errorf("other MDM: %v", err)
	}
	if f.renews+f.fetches != 0 {
		t.Error("touched a device enrolled in another MDM")
	}

	d := (&fakeDevice{info: &shared.MDMInfo{Enrolled: true, ServerURLHost: "x"}}).deps()
	d.OurHost = func() string { return "" }
	if _, err := New(d).Enroll(context.Background(), Request{}); outcomeCode(t, err) != ResultMDMHostUnknown {
		t.Errorf("unknown host: %v", err)
	}
}

// A Windows device (eligibility reported) needs the Windows enroller.
func TestEnroll_WindowsWithoutEnroller(t *testing.T) {
	yes := true
	f := &fakeDevice{info: &shared.MDMInfo{Eligible: &yes, EnrollmentType: "none"}}
	if _, err := New(f.deps()).Enroll(context.Background(), Request{Method: MethodAuto}); outcomeCode(t, err) != ResultUnsupportedOS {
		t.Errorf("err = %v", err)
	}
	if f.fetches+f.renews != 0 {
		t.Error("a Windows device went down the Mac path")
	}
}

func TestEnroll_Unsupported(t *testing.T) {
	d := (&fakeDevice{}).deps()
	d.Collect = func(string) *shared.MDMInfo { return nil }
	if _, err := New(d).Enroll(context.Background(), Request{Method: MethodAuto}); outcomeCode(t, err) != ResultUnsupportedOS {
		t.Errorf("err = %v", err)
	}
}

// Auto picks ADE when ABM assigns the Mac to our server, and waits for it.
func TestEnroll_ADE(t *testing.T) {
	f := &fakeDevice{info: notEnrolled(ptr(true), "mdm.example.com"), afterStart: enrolledOurs}
	out, err := New(f.deps()).Enroll(context.Background(), Request{Method: MethodAuto})
	if err != nil || out.Code != ResultEnrolled || f.renews != 1 || f.fetches != 0 {
		t.Errorf("out %v err %v renews %d fetches %d", out, err, f.renews, f.fetches)
	}

	// Not enrolled within the wait: the task reports it was started.
	f = &fakeDevice{info: notEnrolled(ptr(true), "mdm.example.com")}
	if out, err := New(f.deps()).Enroll(context.Background(), Request{Method: MethodAuto}); err != nil || out.Code != ResultADETriggered {
		t.Errorf("not yet enrolled: %v %v", out, err)
	}
}

// A stale ABM assignment to another MDM is never triggered.
func TestEnroll_ADEAssignedElsewhere(t *testing.T) {
	f := &fakeDevice{info: notEnrolled(ptr(true), "mdm.oldvendor.com")}
	_, err := New(f.deps()).Enroll(context.Background(), Request{Method: MethodAuto})
	if outcomeCode(t, err) != ResultOtherMDM || f.renews != 0 {
		t.Errorf("err %v, renews %d", err, f.renews)
	}
	f = &fakeDevice{info: notEnrolled(ptr(false), "")}
	if _, err := New(f.deps()).Enroll(context.Background(), Request{Method: MethodADE}); outcomeCode(t, err) != ResultADENotAssigned {
		t.Errorf("forced ADE without assignment: %v", err)
	}
	f = &fakeDevice{info: notEnrolled(ptr(true), "mdm.example.com"), renewErr: errors.New("exit 1")}
	if _, err := New(f.deps()).Enroll(context.Background(), Request{Method: MethodAuto}); err == nil || !strings.Contains(err.Error(), "exit 1") {
		t.Errorf("renew failure: %v", err)
	}
}

// The profile path presents to the console user and reports enrolled once
// the user approves. Every presentation fetches a new profile (#545).
func TestEnroll_Profile(t *testing.T) {
	alice := &Session{ID: "501", User: "alice"}
	f := &fakeDevice{info: notEnrolled(ptr(false), ""), console: alice, afterStart: enrolledOurs, clock: time.Unix(1_800_000_000, 0)}
	e := New(f.deps())
	out, err := e.Enroll(context.Background(), Request{Method: MethodAuto})
	if err != nil || out.Code != ResultEnrolled || len(f.presented) != 1 {
		t.Fatalf("out %v err %v presented %d", out, err, len(f.presented))
	}
	p := f.presented[0]
	if p.Name != profileName || string(p.Data) != "<?xml p" || p.Title == "" || !strings.Contains(p.Message, "Install") {
		t.Errorf("presented %+v", p)
	}

	// Asked again right away, with or without force: a new profile each time.
	f.started, f.afterStart = false, nil
	for i, force := range []bool{false, true} {
		out, err = e.Enroll(context.Background(), Request{Method: MethodProfile, Force: force})
		if err != nil || out.Code != ResultProfilePresented || f.fetches != i+2 || len(f.presented) != i+2 {
			t.Errorf("again (force %v): %v %v fetches %d", force, out, err, f.fetches)
		}
	}
}

// The profile is presented only once the user is at the Mac, and fetched
// only then, so its challenge is fresh when they see it.
func TestEnroll_ProfileWaitsForActiveUser(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	f := &fakeDevice{info: notEnrolled(nil, ""), console: &Session{ID: "501", User: "alice"}, clock: start}
	back := start.Add(4 * time.Minute)
	f.active = func() bool { return !f.clock.Before(back) }
	out, err := New(f.deps()).Enroll(context.Background(), Request{Method: MethodProfile})
	if err != nil || out.Code != ResultProfilePresented || f.fetches != 1 {
		t.Fatalf("out %v err %v fetches %d", out, err, f.fetches)
	}
	if f.fetchedWhileIdle {
		t.Error("fetched the profile while the user was away")
	}
}

// A user away for the whole wait gets nothing; the task says why.
func TestEnroll_ProfileUserIdleTimeout(t *testing.T) {
	f := &fakeDevice{info: notEnrolled(nil, ""), console: &Session{ID: "501", User: "alice"}, clock: time.Unix(1_800_000_000, 0)}
	f.active = func() bool { return false }
	start := f.clock
	_, err := New(f.deps()).Enroll(context.Background(), Request{Method: MethodProfile})
	if outcomeCode(t, err) != ResultUserIdleTimeout || !strings.Contains(err.Error(), "alice") {
		t.Errorf("err = %v", err)
	}
	if f.fetches != 0 || len(f.presented) != 0 {
		t.Errorf("fetched %d, presented %d to an idle user", f.fetches, len(f.presented))
	}
	if waited := f.clock.Sub(start); waited < waitActive || waited > waitActive+activePoll {
		t.Errorf("waited %v, want %v", waited, waitActive)
	}
}

// The task's deadline bounds the wait, leaving time to wait for the
// enrollment and report.
func TestEnroll_ProfileWaitWithinDeadline(t *testing.T) {
	f := &fakeDevice{info: notEnrolled(nil, ""), console: &Session{ID: "501", User: "alice"}, clock: time.Unix(1_800_000_000, 0)}
	f.active = func() bool { return false }
	ctx, cancel := context.WithTimeout(context.Background(), deadlineReserve+waitEnrolled/2+2*time.Minute)
	defer cancel()
	start := f.clock
	if _, err := New(f.deps()).Enroll(ctx, Request{Method: MethodProfile}); outcomeCode(t, err) != ResultUserIdleTimeout {
		t.Fatalf("err = %v", err)
	}
	if waited := f.clock.Sub(start); waited > 2*time.Minute+activePoll {
		t.Errorf("waited %v past a deadline that left 2m", waited)
	}

	// No time left at all: one look, then the answer.
	f.sleeps = 0
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := New(f.deps()).Enroll(ctx, Request{Method: MethodProfile}); outcomeCode(t, err) != ResultUserIdleTimeout || f.sleeps != 0 {
		t.Errorf("err %v sleeps %d", err, f.sleeps)
	}
}

func TestEnroll_ProfileNoUser(t *testing.T) {
	f := &fakeDevice{info: notEnrolled(nil, "")}
	if _, err := New(f.deps()).Enroll(context.Background(), Request{Method: MethodAuto}); outcomeCode(t, err) != ResultNoConsoleUser {
		t.Errorf("nobody signed in: %v", err)
	}
	f = &fakeDevice{info: notEnrolled(nil, ""), console: &Session{ID: "501", User: "bob"}, presentErr: session.ErrNoHelper}
	_, err := New(f.deps()).Enroll(context.Background(), Request{Method: MethodAuto})
	if outcomeCode(t, err) != ResultNoConsoleUser || !strings.Contains(err.Error(), "bob") {
		t.Errorf("no helper: %v", err)
	}

	// Someone signs in during the wait.
	f = &fakeDevice{info: notEnrolled(nil, ""), clock: time.Unix(1_800_000_000, 0)}
	d := f.deps()
	d.ConsoleSession = func() (Session, bool) { return Session{ID: "501", User: "carol"}, f.sleeps >= 2 }
	if out, err := New(d).Enroll(context.Background(), Request{Method: MethodProfile}); err != nil || out.Code != ResultProfilePresented {
		t.Errorf("signed in later: %v %v", out, err)
	}
}

// A stopped task stops waiting.
func TestEnroll_ProfileWaitCancelled(t *testing.T) {
	f := &fakeDevice{info: notEnrolled(nil, ""), console: &Session{ID: "501", User: "alice"}}
	f.active = func() bool { return false }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := New(f.deps()).Enroll(ctx, Request{Method: MethodProfile})
	var oe *OutcomeError
	if err == nil || errors.As(err, &oe) || !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func TestEnroll_PayloadHostOverridesConfig(t *testing.T) {
	var got string
	f := &fakeDevice{info: enrolledOurs}
	d := f.deps()
	d.Collect = func(h string) *shared.MDMInfo { got = h; return enrolledOurs }
	if _, err := New(d).Enroll(context.Background(), Request{MDMHost: "mdm.override.com"}); err != nil {
		t.Fatal(err)
	}
	if got != "mdm.override.com" {
		t.Errorf("collected for host %q", got)
	}
}

func TestParseRequest(t *testing.T) {
	r, err := ParseRequest(map[string]interface{}{"method": " ADE ", "mdm_host": "mdm.x", "force": true, "other": 1})
	if err != nil || r.Method != MethodADE || r.MDMHost != "mdm.x" || !r.Force {
		t.Errorf("%+v %v", r, err)
	}
	if r, err := ParseRequest(nil); err != nil || r.Method != MethodAuto {
		t.Errorf("empty payload: %+v %v", r, err)
	}
	for _, bad := range []map[string]interface{}{{"method": "magic"}, {"method": 3}} {
		if _, err := ParseRequest(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}
