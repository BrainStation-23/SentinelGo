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
// crashed agent's changes are undone on the next start (fail open).

import (
	"crypto/x509"
	"errors"
	"strings"
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
)

// Reason is the capability reason for a Redirector or Truster error.
func Reason(err error) string {
	for _, e := range []error{ErrExistingProxy, ErrNeedsMDM, ErrNotImplemented} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return "error"
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
