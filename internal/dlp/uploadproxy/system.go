package uploadproxy

// What the service changes on the device for inspection (#344 phase 2),
// behind two small interfaces so each OS supplies its own:
//
//   - a Redirector points the system proxy setting at the PAC script, and
//     stands down when the device already has a proxy configured (a
//     corporate proxy or an SSE client: two interceptors break things);
//   - a Truster puts the inspection CA in the system trust store, and takes
//     it out when inspection is turned off.
//
// Both leave a note in the config directory of what they changed, so a
// crashed agent's changes are undone on the next start (fail open). On
// Linux the proxy setting is per user, so the session helpers set it
// (sessionRedirector) and keep their own notes.

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Redirector points the system proxy setting at a PAC URL.
type Redirector interface {
	// Apply sets pacURL as the system's proxy auto-config. It returns an
	// error wrapping ErrExistingProxy, and changes nothing, when another
	// proxy is configured.
	Apply(pacURL string) error
	// Remove undoes Apply (and what a crashed agent left). Safe to call
	// when nothing was applied.
	Remove() error
}

// Truster manages the inspection CA in the system trust store.
type Truster interface {
	// Trust adds the CA. It returns an error wrapping ErrNeedsMDM where the
	// OS doesn't let a service trust a root without a user or MDM.
	Trust(ca *CA) error
	// Untrust removes every inspection CA this agent added.
	Untrust() error
}

// Errors a Redirector or Truster reports; their reasons become capability
// values (unsupported:<reason>).
var (
	ErrExistingProxy  = errors.New("existing_proxy")
	ErrNeedsMDM       = errors.New("ca_needs_mdm")
	ErrNotImplemented = errors.New("not_implemented")
	// ErrNoSession: no user session has a helper that could set its proxy.
	ErrNoSession = errors.New("no_graphical_session")
	// ErrUnsupportedDesktop: the sessions' desktops have no proxy setting
	// the agent knows (GNOME, KDE).
	ErrUnsupportedDesktop = errors.New("unsupported_desktop")
	// ErrNoNft: the Linux backstop needs the `nft` command (#426).
	ErrNoNft = errors.New("no_nft")
)

// Reason is the capability reason for a Redirector or Truster error.
func Reason(err error) string {
	for _, e := range []error{ErrExistingProxy, ErrNeedsMDM, ErrNotImplemented, ErrNoSession, ErrUnsupportedDesktop, ErrNoNft} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return "error"
}

// SessionProxySetter asks every user session's helper to point the user's
// desktop proxy at pacURL ("" puts their own setting back) and returns each
// session's reason: "" when applied, else existing_proxy,
// unsupported_desktop, no_answer, ... (ipc.SetProxyResult).
type SessionProxySetter func(ctx context.Context, pacURL string) []string

// sessionProxyWait bounds how long a Redirector waits for the helpers. The
// watchdog calls it every watchdogEvery, and Stop holds the service lock.
var sessionProxyWait = 5 * time.Second

// sessionRedirector redirects through the session helpers (Linux, #426):
// active when at least one session applied it. It stands down per session:
// a user with their own proxy keeps it, and each session's outcome is in
// the sessions list.
type sessionRedirector struct{ set SessionProxySetter }

func (r sessionRedirector) Apply(pacURL string) error {
	if r.set == nil {
		return fmt.Errorf("%w: no session helpers to set the desktop proxy", ErrNotImplemented)
	}
	ctx, cancel := context.WithTimeout(context.Background(), sessionProxyWait)
	defer cancel()
	return sessionsResult(r.set(ctx, pacURL))
}

// Remove asks every helper to put its user's setting back. Failures stay
// per session (a helper also restores when it loses the service or exits),
// so Remove itself always succeeds.
func (r sessionRedirector) Remove() error {
	if r.set == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), sessionProxyWait)
	defer cancel()
	r.set(ctx, "")
	return nil
}

// sessionsResult is the device's redirect from the sessions' reasons: nil
// when any session applied it, else the most telling reason.
func sessionsResult(reasons []string) error {
	if len(reasons) == 0 {
		return fmt.Errorf("%w: no session helper is connected", ErrNoSession)
	}
	counts := map[string]int{}
	for _, r := range reasons {
		if r == "" {
			return nil
		}
		counts[r]++
	}
	for _, e := range []error{ErrExistingProxy, ErrUnsupportedDesktop} {
		if n := counts[e.Error()]; n > 0 {
			return fmt.Errorf("%w: in %d of %d sessions", e, n, len(reasons))
		}
	}
	return fmt.Errorf("no session applied the desktop proxy: %v", counts)
}

// systemTrusts reports whether the system's verifier trusts ca as a root
// (on Windows and macOS Go asks the platform's verifier; on Linux it reads
// the system bundle).
func systemTrusts(ca *CA) bool {
	_, err := ca.Certificate().Verify(x509.VerifyOptions{KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err == nil
}

// caSubjectPrefix starts every inspection CA's common name (newCA), so the
// agent can find its own CAs in a store without touching anyone else's.
const caSubjectPrefix = "SentinelOps Upload Inspection CA"

// isOurCA reports whether der is an inspection CA made by this agent.
func isOurCA(der []byte) bool {
	c, err := x509.ParseCertificate(der)
	if err != nil || !c.IsCA {
		return false
	}
	return len(c.Subject.Organization) == 1 && c.Subject.Organization[0] == "SentinelOps" &&
		strings.HasPrefix(c.Subject.CommonName, caSubjectPrefix)
}
