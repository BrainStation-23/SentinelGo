package uploadproxy

// Linux: the CA goes into the system bundle the distribution builds from
// /usr/local/share/ca-certificates (update-ca-certificates on Debian and
// Ubuntu). The proxy setting is per user (GNOME, KDE), so the session
// helpers point it at the PAC script (#426, sessionRedirector); an nftables
// backstop for apps that ignore it comes later.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"sentinelgo/internal/binpath"
)

// Test seams: where the anchor goes and the bundle update.
var (
	anchorDir      = "/usr/local/share/ca-certificates"
	updateCABundle = func() error {
		// A fixed system path, never a PATH search: this runs as root.
		tool, ok := binpath.Lookup("update-ca-certificates")
		if !ok {
			return fmt.Errorf("%w: update-ca-certificates not found", ErrNotImplemented)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		return exec.CommandContext(ctx, tool).Run() // #nosec G204 -- a fixed system tool, no arguments
	}
)

const anchorName = "sentinelops-upload-inspection.crt"

// NewRedirector returns a Redirector without session helpers: Apply can't
// redirect and Remove has nothing to do (for uninstall: each helper puts
// its user's setting back when it stops).
func NewRedirector(string) Redirector { return sessionRedirector{} }

// platformRedirector redirects through the session helpers.
func platformRedirector(o ServiceOptions) Redirector { return sessionRedirector{set: o.SessionProxy} }

type linuxTruster struct{}

// NewTruster returns this OS's Truster.
func NewTruster() Truster { return linuxTruster{} }

func (linuxTruster) Trust(ca *CA) error {
	if _, err := os.Stat(anchorDir); err != nil {
		return fmt.Errorf("%w: no %s (not a Debian-style trust store)", ErrNotImplemented, anchorDir)
	}
	path := filepath.Join(anchorDir, anchorName)
	if b, err := os.ReadFile(path); err == nil && string(b) == string(ca.CertPEM()) { // #nosec G304 -- our own anchor
		return nil
	}
	if err := writeFileAtomic(path, ca.CertPEM(), 0o644, false); err != nil {
		return fmt.Errorf("write the CA anchor: %w", err)
	}
	if err := updateCABundle(); err != nil {
		return fmt.Errorf("update-ca-certificates: %w", err)
	}
	return nil
}

func (linuxTruster) Untrust() error {
	err := os.Remove(filepath.Join(anchorDir, anchorName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return updateCABundle()
}
