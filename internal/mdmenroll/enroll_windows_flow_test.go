package mdmenroll

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"sentinelgo/internal/dlp/ipc"
	"sentinelgo/internal/osinfo/shared"
)

// windowsDevice wires an Enroller for a Windows PC (eligibility reported).
type windowsDevice struct {
	fakeDevice
	registerErr error
	registered  []string // upn|url|token
	links       []ipc.OpenURL
}

func (w *windowsDevice) deps() Deps {
	d := w.fakeDevice.deps()
	d.FetchWindowsEnrollment = func(context.Context) (WindowsEnrollment, error) {
		return WindowsEnrollment{DiscoveryURL: "https://mdm.example.com/EnrollmentServer/Discovery.svc", UPN: "alice@corp.com", AccessToken: "tok"}, nil
	}
	d.RegisterWindows = func(upn, u, tok string) error {
		w.registered = append(w.registered, upn+"|"+u+"|"+tok)
		if w.registerErr == nil {
			w.started = true
		}
		return w.registerErr
	}
	d.PresentURL = func(_ context.Context, _ string, u ipc.OpenURL) error {
		w.links = append(w.links, u)
		return nil
	}
	return d
}

func eligibleWindows(eligible bool, reason string) *shared.MDMInfo {
	return &shared.MDMInfo{Eligible: &eligible, IneligibleReason: reason, EnrollmentType: "none"}
}

var enrolledOursWindows = func() *shared.MDMInfo {
	yes := true
	return &shared.MDMInfo{Eligible: &yes, Enrolled: true, IsOurServer: true, ServerURLHost: "mdm.example.com"}
}()

func TestEnrollWindows_Silent(t *testing.T) {
	w := &windowsDevice{fakeDevice: fakeDevice{info: eligibleWindows(true, ""), afterStart: enrolledOursWindows}}
	out, err := New(w.deps()).Enroll(context.Background(), Request{Method: MethodAuto})
	if err != nil || out.Code != ResultEnrolled || len(w.registered) != 1 || len(w.links) != 0 {
		t.Fatalf("out %v err %v registered %v links %v", out, err, w.registered, w.links)
	}
	if w.registered[0] != "alice@corp.com|https://mdm.example.com/EnrollmentServer/Discovery.svc|tok" {
		t.Errorf("registered with %q", w.registered[0])
	}
}

// When silent enrollment fails, the console user gets the enrollment link.
func TestEnrollWindows_FallbackLink(t *testing.T) {
	w := &windowsDevice{registerErr: errors.New("RegisterDeviceWithManagement: 0x80180002"),
		fakeDevice: fakeDevice{info: eligibleWindows(true, ""), console: &Session{ID: "3", User: "the user of session 3"}}}
	out, err := New(w.deps()).Enroll(context.Background(), Request{Method: MethodAuto})
	if err != nil || out.Code != ResultLinkPresented || len(w.links) != 1 || !strings.Contains(out.Detail, "0x80180002") {
		t.Fatalf("out %v err %v links %v", out, err, w.links)
	}
	link, perr := url.Parse(w.links[0].URL)
	if perr != nil || link.Scheme != "ms-device-enrollment" {
		t.Fatalf("link %q", w.links[0].URL)
	}
	q := link.Query()
	if q.Get("mode") != "mdm" || q.Get("username") != "alice@corp.com" || q.Get("servername") != "https://mdm.example.com/EnrollmentServer/Discovery.svc" {
		t.Errorf("link query %v", q)
	}
	if strings.Contains(w.links[0].URL, "tok") {
		t.Error("the access token is in the user-visible link")
	}

	// No console user: the silent failure is the error.
	w = &windowsDevice{registerErr: errors.New("0x80180002"), fakeDevice: fakeDevice{info: eligibleWindows(true, "")}}
	if _, err := New(w.deps()).Enroll(context.Background(), Request{}); err == nil || !strings.Contains(err.Error(), "silent enrollment failed") {
		t.Errorf("no console: %v", err)
	}
}

func TestEnrollWindows_Refusals(t *testing.T) {
	w := &windowsDevice{fakeDevice: fakeDevice{info: eligibleWindows(false, "home_edition")}}
	_, err := New(w.deps()).Enroll(context.Background(), Request{})
	if outcomeCode(t, err) != ResultIneligible || !strings.Contains(err.Error(), "home_edition") || len(w.registered) != 0 {
		t.Errorf("home: %v", err)
	}
	w = &windowsDevice{fakeDevice: fakeDevice{info: eligibleWindows(true, "")}}
	d := w.deps()
	d.OurHost = func() string { return "" }
	if _, err := New(d).Enroll(context.Background(), Request{}); outcomeCode(t, err) != ResultMDMHostUnknown {
		t.Errorf("no host: %v", err)
	}
	d = w.deps()
	d.FetchWindowsEnrollment = func(context.Context) (WindowsEnrollment, error) { return WindowsEnrollment{}, errors.New("rpc down") }
	if _, err := New(d).Enroll(context.Background(), Request{}); err == nil || !strings.Contains(err.Error(), "rpc down") || len(w.registered) != 0 {
		t.Errorf("fetch failure: %v", err)
	}
}
