// Package mdmenroll starts MDM enrollment of the device: the mdm-enroll
// native task (#350). The agent never speaks the MDM protocol; it gets the
// OS's own MDM client going, by the best path the device allows:
//
//   - A Mac that Apple Business Manager assigns to our MDM server re-enrolls
//     through Automated Device Enrollment (`profiles renew -type enrollment`).
//   - Any other Mac gets a single-use enrollment profile from the backend,
//     presented to the console user through their session helper. macOS 11+
//     won't install an MDM profile silently; the user must approve it.
//
// A device already enrolled in another MDM is never touched.
package mdmenroll

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"sentinelgo/internal/dlp/ipc"
	"sentinelgo/internal/dlp/session"
	"sentinelgo/internal/osinfo/mdm"
	"sentinelgo/internal/osinfo/shared"
)

// Methods in the task payload.
const (
	MethodAuto    = "auto"
	MethodADE     = "ade"
	MethodProfile = "profile"
)

// Outcome codes (contract v1). The first group are successes; the rest fail
// the task.
const (
	ResultAlreadyEnrolled  = "already_enrolled"
	ResultADETriggered     = "ade_triggered"
	ResultProfilePresented = "profile_presented"
	ResultEnrolled         = "enrolled"

	ResultOtherMDM       = "other_mdm"
	ResultUnsupportedOS  = "unsupported_os"
	ResultNoConsoleUser  = "no_console_user"
	ResultADENotAssigned = "ade_not_assigned"
	ResultMDMHostUnknown = "mdm_host_unknown"
)

// Outcome is the task's result: a contract code and a readable detail.
type Outcome struct {
	Code   string
	Detail string
}

func (o Outcome) String() string { return o.Code + ": " + o.Detail }

// OutcomeError is an Outcome that fails the task.
type OutcomeError struct{ Outcome }

func (e *OutcomeError) Error() string { return e.String() }

func fail(code, format string, a ...any) error {
	return &OutcomeError{Outcome{Code: code, Detail: fmt.Sprintf(format, a...)}}
}

// Request is the parsed task payload.
type Request struct {
	Method  string // MethodAuto (default), MethodADE or MethodProfile
	MDMHost string // overrides the config's mdm_host
	Force   bool   // present the profile again even if it was shown today
}

// ParseRequest validates the mdm-enroll payload. Unknown keys are ignored.
func ParseRequest(p map[string]interface{}) (Request, error) {
	r := Request{Method: MethodAuto}
	if v, ok := p["method"]; ok && v != nil {
		s, ok := v.(string)
		if !ok {
			return r, errors.New("mdm-enroll: payload.method must be a string")
		}
		switch s = strings.ToLower(strings.TrimSpace(s)); s {
		case "", MethodAuto:
		case MethodADE, MethodProfile:
			r.Method = s
		default:
			return r, fmt.Errorf("mdm-enroll: unknown method %q (auto, ade or profile)", s)
		}
	}
	if s, ok := p["mdm_host"].(string); ok {
		r.MDMHost = strings.TrimSpace(s)
	}
	r.Force, _ = p["force"].(bool)
	return r, nil
}

// Session is the console user's session.
type Session struct {
	ID   string // what the session helpers report as SessionID (the uid on macOS)
	User string
}

// Deps are the enroller's connections to the device and the backend.
type Deps struct {
	// OurHost returns the config's mdm_host.
	OurHost func() string
	// Collect reads the device's MDM state (mdm.Collect).
	Collect func(ourHost string) *shared.MDMInfo
	// FetchProfile gets this device's enrollment profile from the backend.
	FetchProfile func(ctx context.Context) ([]byte, error)
	// Present shows a profile to the user of a session (session.Service.OpenProfile).
	Present func(ctx context.Context, sessionID string, p ipc.OpenProfile) error
	// ConsoleSession returns the user at the console; false when nobody is.
	ConsoleSession func() (Session, bool)
	// RenewADE runs `profiles renew -type enrollment`.
	RenewADE func(ctx context.Context) error
	// Now and Sleep; defaults are the real clock.
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
}

// Timing of the enroller; vars so tests can shorten them.
var (
	// waitEnrolled is how long a task waits for the enrollment to finish
	// after starting it. A user who approves later shows up in the inventory.
	waitEnrolled = 2 * time.Minute
	pollEvery    = 10 * time.Second
	// promptEvery limits how often one user is shown the profile.
	promptEvery = 24 * time.Hour
)

// profileName is the file the user sees in System Settings' download list.
const profileName = "SentinelOps-Enrollment.mobileconfig"

const (
	presentTitle   = "Enroll this Mac in device management"
	presentMessage = "Your organization's management profile was downloaded. Open System Settings, then General > Device Management (Privacy & Security > Profiles on older macOS), and install it."
)

// Enroller runs mdm-enroll. It is safe for concurrent use.
type Enroller struct {
	d          Deps
	mu         sync.Mutex
	lastPrompt map[string]time.Time // user -> when the profile was presented
}

// New returns an Enroller; zero Now/Sleep default to the real clock.
func New(d Deps) *Enroller {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Sleep == nil {
		d.Sleep = sleep
	}
	if d.Collect == nil {
		d.Collect = mdm.Collect
	}
	return &Enroller{d: d, lastPrompt: map[string]time.Time{}}
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Enroll starts enrollment as req asks and waits a little for it to finish.
// A failed outcome is an *OutcomeError.
func (e *Enroller) Enroll(ctx context.Context, req Request) (Outcome, error) {
	host := req.MDMHost
	if host == "" && e.d.OurHost != nil {
		host = e.d.OurHost()
	}
	info := e.d.Collect(host)
	if info == nil {
		return Outcome{}, fail(ResultUnsupportedOS, "MDM enrollment by the agent isn't supported on this platform")
	}
	if info.Enrolled {
		switch {
		case host == "":
			return Outcome{}, fail(ResultMDMHostUnknown, "the device is enrolled with %s, and mdm_host isn't set, so the agent can't tell whether that is this deployment's MDM", orUnknown(info.ServerURLHost))
		case info.IsOurServer:
			return Outcome{ResultAlreadyEnrolled, "enrolled with " + info.ServerURLHost}, nil
		default:
			return Outcome{}, fail(ResultOtherMDM, "the device is enrolled with another MDM (%s); it isn't changed", orUnknown(info.ServerURLHost))
		}
	}

	method := req.Method
	if method == MethodAuto {
		method = MethodProfile
		if info.ADEAssigned != nil && *info.ADEAssigned {
			method = MethodADE
		}
	}
	var started Outcome
	var err error
	if method == MethodADE {
		started, err = e.startADE(ctx, info, host)
	} else {
		started, err = e.presentProfile(ctx, req.Force)
	}
	if err != nil || started.Code == ResultAlreadyEnrolled {
		return started, err
	}
	return e.waitForEnrollment(ctx, host, started), nil
}

func (e *Enroller) startADE(ctx context.Context, info *shared.MDMInfo, host string) (Outcome, error) {
	if info.ADEAssigned == nil || !*info.ADEAssigned {
		return Outcome{}, fail(ResultADENotAssigned, "Apple Business Manager doesn't assign this Mac to an MDM server; use the profile method")
	}
	if host == "" {
		return Outcome{}, fail(ResultMDMHostUnknown, "mdm_host isn't set, so the agent can't check that Apple Business Manager assigns this Mac to this deployment's MDM")
	}
	// A stale assignment would enroll the Mac into someone else's MDM.
	if info.ADEServerHost != "" && !mdm.IsOurServer(info.ADEServerHost, host) {
		return Outcome{}, fail(ResultOtherMDM, "Apple Business Manager assigns this Mac to %s, not to this deployment's MDM; change the Mac's MDM server in Apple Business Manager", info.ADEServerHost)
	}
	if e.d.RenewADE == nil {
		return Outcome{}, fail(ResultUnsupportedOS, "ADE re-enrollment isn't available on this platform")
	}
	if err := e.d.RenewADE(ctx); err != nil {
		return Outcome{}, fmt.Errorf("mdm-enroll: starting ADE enrollment: %w", err)
	}
	return Outcome{ResultADETriggered, "macOS is asking the user to enroll the Mac"}, nil
}

func (e *Enroller) presentProfile(ctx context.Context, force bool) (Outcome, error) {
	if e.d.ConsoleSession == nil || e.d.Present == nil || e.d.FetchProfile == nil {
		return Outcome{}, fail(ResultUnsupportedOS, "profile enrollment isn't available on this platform")
	}
	sess, ok := e.d.ConsoleSession()
	if !ok {
		return Outcome{}, fail(ResultNoConsoleUser, "nobody is signed in at the console; try again when a user is")
	}
	now := e.d.Now()
	e.mu.Lock()
	last, seen := e.lastPrompt[sess.User]
	e.mu.Unlock()
	if seen && !force && now.Sub(last) < promptEvery {
		return Outcome{ResultProfilePresented, fmt.Sprintf("already presented to %s at %s; it's shown again after %s, or now with force", sess.User, last.UTC().Format(time.RFC3339), last.Add(promptEvery).UTC().Format(time.RFC3339))}, nil
	}

	data, err := e.d.FetchProfile(ctx)
	if err != nil {
		return Outcome{}, fmt.Errorf("mdm-enroll: getting the enrollment profile: %w", err)
	}
	err = e.d.Present(ctx, sess.ID, ipc.OpenProfile{Name: profileName, Data: data, Title: presentTitle, Message: presentMessage})
	if errors.Is(err, session.ErrNoHelper) {
		return Outcome{}, fail(ResultNoConsoleUser, "%s is signed in, but their session helper isn't connected", sess.User)
	}
	if err != nil {
		return Outcome{}, fmt.Errorf("mdm-enroll: presenting the profile to %s: %w", sess.User, err)
	}
	e.mu.Lock()
	e.lastPrompt[sess.User] = now
	e.mu.Unlock()
	return Outcome{ResultProfilePresented, "opened in " + sess.User + "'s session; waiting for them to install it in System Settings"}, nil
}

// waitForEnrollment polls the MDM state for a while; it returns enrolled
// when the device enrolls with our server, otherwise the started outcome.
func (e *Enroller) waitForEnrollment(ctx context.Context, host string, started Outcome) Outcome {
	deadline := e.d.Now().Add(waitEnrolled)
	for e.d.Now().Before(deadline) {
		if e.d.Sleep(ctx, pollEvery) != nil {
			break
		}
		if info := e.d.Collect(host); info != nil && info.Enrolled && info.IsOurServer {
			return Outcome{ResultEnrolled, "enrolled with " + info.ServerURLHost}
		}
	}
	return started
}

func orUnknown(s string) string {
	if s == "" {
		return "an unknown server"
	}
	return s
}
