// Package mdmenroll starts MDM enrollment of the device: the mdm-enroll
// native task (#350). The agent never speaks the MDM protocol; it gets the
// OS's own MDM client going, by the best path the device allows:
//
//   - A Mac that Apple Business Manager assigns to our MDM server re-enrolls
//     through Automated Device Enrollment (`profiles renew -type enrollment`).
//   - Any other Mac gets a single-use enrollment profile from the backend,
//     presented to the console user through their session helper. macOS 11+
//     won't install an MDM profile silently; the user must approve it. So
//     the agent waits until the user is at the Mac, fetches a new profile
//     every time, opens System Settings where it is installed, and offers
//     Enroll now until the Mac is enrolled (#545).
//
// A device already enrolled in another MDM is never touched.
package mdmenroll

import (
	"context"
	"errors"
	"fmt"
	"net/url"
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

	ResultLinkPresented = "link_presented" // Windows: the enrollment link opened in the user's session

	ResultIneligible     = "ineligible" // Windows Home, Server, or blocked by policy
	ResultOtherMDM       = "other_mdm"
	ResultUnsupportedOS  = "unsupported_os"
	ResultNoConsoleUser  = "no_console_user"
	ResultADENotAssigned = "ade_not_assigned"
	ResultMDMHostUnknown = "mdm_host_unknown"
	// ResultUserIdleTimeout: a user was signed in, but idle or with the
	// screen locked for the whole wait, so the profile wasn't presented.
	ResultUserIdleTimeout = "user_idle_timeout"
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
	// Force is accepted for older consoles. Every presentation now fetches a
	// new profile, so there is nothing to force.
	Force bool
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
	// UserActive says whether the user of s is at the Mac: recent keyboard
	// or mouse input, the screen unlocked. nil means always.
	UserActive func(s Session) bool
	// Offer asks the user of a session whether to enroll now (the Enroll
	// now dialog, session.Service.OfferEnroll); nil means no offers.
	Offer func(ctx context.Context, sessionID string, o ipc.OfferEnroll) (bool, error)
	// OfferState is the file that keeps the offer's state across restarts;
	// "" keeps it in memory.
	OfferState string
	// RenewADE runs `profiles renew -type enrollment`.
	RenewADE func(ctx context.Context) error
	// Windows (#356). FetchWindowsEnrollment gets the discovery URL, UPN and
	// single-use access token from the backend; RegisterWindows enrolls
	// silently (RegisterDeviceWithManagement); PresentURL opens the
	// ms-device-enrollment: link in a user's session when that fails. nil
	// RegisterWindows means this platform can't.
	FetchWindowsEnrollment func(ctx context.Context) (WindowsEnrollment, error)
	RegisterWindows        func(upn, discoveryURL, accessToken string) error
	PresentURL             func(ctx context.Context, sessionID string, u ipc.OpenURL) error
	// Now and Sleep; defaults are the real clock.
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
}

// Timing of the enroller; vars so tests can shorten them. Tasks run one at
// a time, so a task's waits hold up the device's other tasks: they are
// bounded here, and by the task's deadline.
var (
	// waitActive is how long a task waits for the console user to be at
	// the Mac before giving up with user_idle_timeout.
	waitActive = 10 * time.Minute
	activePoll = 30 * time.Second
	// waitEnrolled is how long a task waits for the enrollment to finish
	// after starting it. A user who approves later shows up in the inventory.
	waitEnrolled = 5 * time.Minute
	pollEvery    = 10 * time.Second
	// deadlineReserve is the part of the task's deadline left for
	// reporting the result.
	deadlineReserve = 30 * time.Second
)

// profileName is the file the user sees in System Settings' download list.
const profileName = "SentinelOps-Enrollment.mobileconfig"

const (
	presentTitle   = "Enroll this Mac in device management"
	presentMessage = "System Settings is open at Device Management. Double-click the downloaded enrollment profile, click Install, then enter your Mac password."
)

// Enroller runs mdm-enroll. It is safe for concurrent use.
type Enroller struct {
	d Deps
	// presentMu lets one profile be fetched and presented at a time: a task
	// and an Enroll now click don't both present one.
	presentMu sync.Mutex

	mu    sync.Mutex // guards offer, tasks and presents
	offer *offerState
	// tasks counts profile tasks waiting for the user, presenting or
	// waiting for the enrollment; no offers are made meanwhile.
	tasks int
	// presents counts presentations, so an Enroll now click that comes
	// after another presentation doesn't supersede that profile.
	presents uint64
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
	return &Enroller{d: d}
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
		e.disarm() // no more Enroll now offers, whichever MDM it is
		switch {
		case host == "":
			return Outcome{}, fail(ResultMDMHostUnknown, "the device is enrolled with %s, and mdm_host isn't set, so the agent can't tell whether that is this deployment's MDM", orUnknown(info.ServerURLHost))
		case info.IsOurServer:
			return Outcome{ResultAlreadyEnrolled, "enrolled with " + info.ServerURLHost}, nil
		default:
			return Outcome{}, fail(ResultOtherMDM, "the device is enrolled with another MDM (%s); it isn't changed", orUnknown(info.ServerURLHost))
		}
	}

	// A Windows device (it reports its edition's eligibility) enrolls its own way.
	if info.Eligible != nil {
		started, err := e.enrollWindows(ctx, info, host)
		if err != nil || started.Code == ResultEnrolled {
			return started, err
		}
		return e.waitForEnrollment(ctx, host, started), nil
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
		e.taskBusy(1)
		defer e.taskBusy(-1)
		started, err = e.presentProfile(ctx)
	}
	if err != nil || started.Code == ResultAlreadyEnrolled {
		return started, err
	}
	return e.waitForEnrollment(ctx, host, started), nil
}

// enrollWindows enrolls a Windows device silently, as SYSTEM, with a token
// from the backend; if that fails, it opens the enrollment link for the
// console user so they can finish in Settings.
func (e *Enroller) enrollWindows(ctx context.Context, info *shared.MDMInfo, host string) (Outcome, error) {
	if e.d.RegisterWindows == nil || e.d.FetchWindowsEnrollment == nil {
		return Outcome{}, fail(ResultUnsupportedOS, "MDM enrollment of Windows devices isn't available on this platform")
	}
	if !*info.Eligible {
		return Outcome{}, fail(ResultIneligible, "this device can't enroll in MDM (%s)", info.IneligibleReason)
	}
	if host == "" {
		return Outcome{}, fail(ResultMDMHostUnknown, "mdm_host isn't set, so the agent can't confirm the enrollment")
	}
	creds, err := e.d.FetchWindowsEnrollment(ctx)
	if err != nil {
		return Outcome{}, fmt.Errorf("mdm-enroll: getting the enrollment token: %w", err)
	}
	regErr := e.d.RegisterWindows(creds.UPN, creds.DiscoveryURL, creds.AccessToken)
	if regErr == nil {
		if after := e.d.Collect(host); after != nil && after.Enrolled && after.IsOurServer {
			return Outcome{ResultEnrolled, "enrolled silently with " + after.ServerURLHost}, nil
		}
		return Outcome{ResultEnrolled, "enrollment registered; the device reports it at its first MDM session"}, nil
	}

	// Fall back to the user: open the enrollment link in their session.
	sess, ok := e.consoleSession()
	if !ok || e.d.PresentURL == nil {
		return Outcome{}, fmt.Errorf("mdm-enroll: silent enrollment failed: %w", regErr)
	}
	link := enrollmentLink(creds.UPN, creds.DiscoveryURL)
	if err := e.d.PresentURL(ctx, sess.ID, ipc.OpenURL{URL: link, Title: windowsTitle, Message: windowsMessage}); err != nil {
		return Outcome{}, fmt.Errorf("mdm-enroll: silent enrollment failed (%v), and the enrollment link couldn't be opened for %s: %w", regErr, sess.User, err)
	}
	return Outcome{ResultLinkPresented, fmt.Sprintf("silent enrollment failed (%v); opened the enrollment link in %s's session", regErr, sess.User)}, nil
}

func (e *Enroller) consoleSession() (Session, bool) {
	if e.d.ConsoleSession == nil {
		return Session{}, false
	}
	return e.d.ConsoleSession()
}

const (
	windowsTitle   = "Enroll this PC in device management"
	windowsMessage = "Settings opened to connect this PC to your organization's device management. Sign in with your work account to finish."
)

// enrollmentLink is the ms-device-enrollment: URI that opens Settings'
// "Enroll only in device management" with the user and server filled in.
func enrollmentLink(upn, discoveryURL string) string {
	q := url.Values{}
	q.Set("mode", "mdm")
	q.Set("username", upn)
	q.Set("servername", discoveryURL)
	return "ms-device-enrollment:?" + q.Encode()
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

// presentProfile waits for the console user to be at the Mac, then
// presents a new profile to them. From then on they are offered Enroll now
// until the Mac is enrolled.
func (e *Enroller) presentProfile(ctx context.Context) (Outcome, error) {
	if e.d.ConsoleSession == nil || e.d.Present == nil || e.d.FetchProfile == nil {
		return Outcome{}, fail(ResultUnsupportedOS, "profile enrollment isn't available on this platform")
	}
	e.arm()
	sess, err := e.activeSession(ctx)
	if err != nil {
		return Outcome{}, err
	}
	return e.present(ctx, sess)
}

// present fetches a new profile and presents it to the user of sess. A
// profile is single-use and goes stale, so one is never presented twice.
func (e *Enroller) present(ctx context.Context, sess Session) (Outcome, error) {
	e.presentMu.Lock()
	defer e.presentMu.Unlock()
	return e.presentLocked(ctx, sess)
}

// presentLocked is present with presentMu held.
func (e *Enroller) presentLocked(ctx context.Context, sess Session) (Outcome, error) {
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
	e.presents++
	e.mu.Unlock()
	e.shown(sess.User)
	return Outcome{ResultProfilePresented, "opened in " + sess.User + "'s session with System Settings at Device Management; waiting for them to install it"}, nil
}

// activeSession waits until the console user is at the Mac, for up to
// waitActive and within the task's deadline. It fails with no_console_user
// when nobody signed in during the wait, and user_idle_timeout when
// someone did but was away the whole time.
func (e *Enroller) activeSession(ctx context.Context) (Session, error) {
	wait := e.within(ctx, waitActive, deadlineReserve+waitEnrolled/2)
	until := e.d.Now().Add(wait)
	var last Session
	seen := false
	for {
		if s, ok := e.d.ConsoleSession(); ok {
			if e.d.UserActive == nil || e.d.UserActive(s) {
				return s, nil
			}
			last, seen = s, true
		}
		if !e.d.Now().Before(until) {
			break
		}
		if err := e.d.Sleep(ctx, activePoll); err != nil {
			return Session{}, fmt.Errorf("mdm-enroll: stopped while waiting for the user: %w", err)
		}
	}
	if !seen {
		return Session{}, fail(ResultNoConsoleUser, "nobody was signed in at the console for %s; try again when a user is", wait.Round(time.Second))
	}
	return Session{}, fail(ResultUserIdleTimeout, "%s was away (idle, or the screen locked) for %s, so the profile wasn't presented; they're offered Enroll now when they're back", last.User, wait.Round(time.Second))
}

// within bounds want by ctx's deadline, keeping reserve for what follows.
func (e *Enroller) within(ctx context.Context, want, reserve time.Duration) time.Duration {
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl) - reserve; left < want {
			return max(left, 0)
		}
	}
	return want
}

// waitForEnrollment polls the MDM state for a while; it returns enrolled
// when the device enrolls with our server, otherwise the started outcome.
func (e *Enroller) waitForEnrollment(ctx context.Context, host string, started Outcome) Outcome {
	deadline := e.d.Now().Add(e.within(ctx, waitEnrolled, deadlineReserve))
	for e.d.Now().Before(deadline) {
		if e.d.Sleep(ctx, pollEvery) != nil {
			break
		}
		if info := e.d.Collect(host); info != nil && info.Enrolled && info.IsOurServer {
			e.disarm()
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
