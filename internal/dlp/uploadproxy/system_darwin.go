package uploadproxy

// macOS: the PAC script is set as each network service's automatic proxy
// configuration (networksetup). A root daemon can't trust a root CA in the
// System keychain without a user's authorisation (macOS 11+), so trusting
// the CA is MDM's job (a certificate payload from the Apple MDM server,
// Compliance-OS#533); the agent only checks whether it is trusted.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const redirectNote = "upload-redirect.json"

// Test seam: networksetup.
var runNetworksetup = func(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "/usr/sbin/networksetup", args...).Output() // #nosec G204 -- fixed tool; service names from networksetup itself
}

type macRedirector struct{ dir string }

// NewRedirector returns this OS's Redirector; dir holds its note.
func NewRedirector(dir string) Redirector { return &macRedirector{dir: dir} }

// platformRedirector is the machine-wide setting; helpers aren't needed.
func platformRedirector(o ServiceOptions) Redirector { return NewRedirector(o.ConfigDir) }

type macNote struct {
	PACURL   string   `json:"pac_url"`
	Services []string `json:"services"` // where the agent turned the auto proxy on
}

func (r *macRedirector) notePath() string { return filepath.Join(r.dir, redirectNote) }

// services lists the enabled network services.
func services() ([]string, error) {
	out, err := runNetworksetup("-listallnetworkservices")
	if err != nil {
		return nil, fmt.Errorf("networksetup: %w", err)
	}
	var svcs []string
	for i, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if i == 0 || line == "" || strings.HasPrefix(line, "*") { // a header line; disabled services start with *
			continue
		}
		svcs = append(svcs, line)
	}
	return svcs, nil
}

// enabled reports "Enabled: Yes" in networksetup output.
func enabled(out []byte) bool {
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "Enabled" {
			return strings.TrimSpace(v) == "Yes"
		}
	}
	return false
}

// autoProxyURL is the URL in -getautoproxyurl output ("" when none).
func autoProxyURL(out []byte) string {
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "URL" {
			if v = strings.TrimSpace(v); v != "(null)" {
				return v
			}
		}
	}
	return ""
}

// foreignProxy reports another proxy on service s: a web or secure web
// proxy, or an auto proxy at another URL than ours (auto is s's
// -getautoproxyurl output).
func foreignProxy(s string, auto []byte, pacURL string) bool {
	if enabled(auto) && autoProxyURL(auto) != pacURL {
		return true
	}
	for _, flag := range []string{"-getwebproxy", "-getsecurewebproxy"} {
		if out, err := runNetworksetup(flag, s); err == nil && enabled(out) {
			return true
		}
	}
	return false
}

func (r *macRedirector) Apply(pacURL string) (bool, error) {
	if n, ok := r.readNote(); ok && n.PACURL == pacURL {
		return r.check(n)
	}
	if err := r.Remove(); err != nil {
		return false, err
	}
	svcs, err := services()
	if err != nil {
		return false, err
	}
	for _, s := range svcs {
		for _, flag := range []string{"-getwebproxy", "-getsecurewebproxy", "-getautoproxyurl"} {
			if out, err := runNetworksetup(flag, s); err == nil && enabled(out) {
				return false, fmt.Errorf("%w: %s on a network service", ErrExistingProxy, flag[4:])
			}
		}
	}
	if err := r.writeNote(macNote{PACURL: pacURL, Services: svcs}); err != nil {
		return false, err
	}
	for _, s := range svcs {
		if _, err := runNetworksetup("-setautoproxyurl", s, pacURL); err != nil {
			_ = r.Remove()
			return false, fmt.Errorf("set the auto proxy: %w", err)
		}
	}
	return false, nil
}

// check is Apply once the note says n.PACURL is applied: it trusts the
// network services, not the note (#477). The setting belongs to each
// service, so turning it off in System Settings, or a service added since
// (a USB adapter, a VPN), loses it. Each enabled service still pointing at
// the PAC is left alone (reads only); one without it, and without another
// proxy, gets it again and joins the note so Remove turns it off too; one
// with another proxy is someone else's now: left alone, and Apply reports
// ErrExistingProxy, as on Windows.
func (r *macRedirector) check(n macNote) (bool, error) {
	svcs, err := services()
	if err != nil {
		return false, err
	}
	var lost []string
	var theirs error
	for _, s := range svcs {
		out, err := runNetworksetup("-getautoproxyurl", s)
		if err != nil {
			continue // can't tell: leave it until the next check
		}
		switch {
		case enabled(out) && autoProxyURL(out) == n.PACURL:
		case foreignProxy(s, out, n.PACURL):
			theirs = fmt.Errorf("%w: another proxy on network service %q", ErrExistingProxy, s)
		default:
			lost = append(lost, s)
		}
	}
	if len(lost) == 0 {
		return false, theirs
	}
	known := map[string]bool{}
	for _, s := range n.Services {
		known[s] = true
	}
	added := false
	for _, s := range lost {
		if !known[s] {
			n.Services, added = append(n.Services, s), true
		}
	}
	if added {
		// The note first, as in Apply: a crash is then still undone.
		if err := r.writeNote(n); err != nil {
			return false, err
		}
	}
	for _, s := range lost {
		if _, err := runNetworksetup("-setautoproxyurl", s, n.PACURL); err != nil {
			return false, fmt.Errorf("set the auto proxy again: %w", err)
		}
	}
	return true, theirs
}

func (r *macRedirector) Remove() error {
	n, ok := r.readNote()
	if !ok {
		return nil
	}
	for _, s := range n.Services {
		out, err := runNetworksetup("-getautoproxyurl", s)
		if err != nil || !strings.Contains(string(out), n.PACURL) {
			continue // gone, or changed by someone else since: theirs now
		}
		_, _ = runNetworksetup("-setautoproxystate", s, "off")
	}
	if err := os.Remove(r.notePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove the redirect note: %w", err)
	}
	return nil
}

func (r *macRedirector) readNote() (macNote, bool) {
	b, err := os.ReadFile(r.notePath())
	if err != nil {
		return macNote{}, false
	}
	var n macNote
	if json.Unmarshal(b, &n) != nil || n.PACURL == "" {
		return macNote{}, false
	}
	return n, true
}

func (r *macRedirector) writeNote(n macNote) error {
	b, err := json.Marshal(n)
	if err != nil {
		return err
	}
	return writeFileAtomic(r.notePath(), b, 0o600, true)
}

type macTruster struct{}

// NewTruster returns this OS's Truster.
func NewTruster() Truster { return macTruster{} }

func (macTruster) Trust(ca *CA) error {
	if systemTrusts(ca) {
		return nil // trusted through an MDM profile
	}
	return fmt.Errorf("%w: deliver the inspection CA in an MDM certificate payload", ErrNeedsMDM)
}

// Untrust has nothing to remove: the agent never adds the CA on macOS (an
// MDM profile does, and removing the profile removes it).
func (macTruster) Untrust() error { return nil }
