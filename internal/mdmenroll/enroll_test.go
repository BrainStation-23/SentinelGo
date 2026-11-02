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
		FetchProfile: func(context.Context) ([]byte, error) { f.fetches++; return []byte("<?xml p"), nil },
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

// The profile path presents to the console user, at most once a day unless
// forced, and reports enrolled once the user approves.
func TestEnroll_Profile(t *testing.T) {
	alice := &Session{ID: "501", User: "alice"}
	f := &fakeDevice{info: notEnrolled(ptr(false), ""), console: alice, afterStart: enrolledOurs, clock: time.Unix(1_800_000_000, 0)}
	e := New(f.deps())
	out, err := e.Enroll(context.Background(), Request{Method: MethodAuto})
	if err != nil || out.Code != ResultEnrolled || len(f.presented) != 1 {
		t.Fatalf("out %v err %v presented %d", out, err, len(f.presented))
	}
	p := f.presented[0]
	if p.Name != profileName || string(p.Data) != "<?xml p" || p.Title == "" {
		t.Errorf("presented %+v", p)
	}

	// Again within a day: no new prompt, no new profile.
	f.started, f.afterStart = false, nil
	out, err = e.Enroll(context.Background(), Request{Method: MethodProfile})
	if err != nil || out.Code != ResultProfilePresented || f.fetches != 1 || !strings.Contains(out.Detail, "already presented") {
		t.Errorf("second: %v %v fetches %d", out, err, f.fetches)
	}
	// force presents it again.
	if out, err := e.Enroll(context.Background(), Request{Method: MethodProfile, Force: true}); err != nil || f.fetches != 2 || out.Code != ResultProfilePresented {
		t.Errorf("forced: %v %v fetches %d", out, err, f.fetches)
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
