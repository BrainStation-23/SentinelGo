package uploadproxy

// Linux: the CA goes into the system bundle the distribution builds from
// /usr/local/share/ca-certificates (update-ca-certificates on Debian and
// Ubuntu). Redirecting traffic (nftables, #344) is not done yet; until then
// clients are pointed at the proxy explicitly.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Test seams: where the anchor goes and the bundle update.
var (
	anchorDir      = "/usr/local/share/ca-certificates"
	updateCABundle = func() error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		return exec.CommandContext(ctx, "update-ca-certificates").Run()
	}
)

const anchorName = "sentinelops-upload-inspection.crt"

type linuxRedirector struct{}

// NewRedirector returns this OS's Redirector.
func NewRedirector(string) Redirector { return linuxRedirector{} }

func (linuxRedirector) Apply(string) error {
	return fmt.Errorf("%w: redirect on Linux comes with nftables (#344)", ErrNotImplemented)
}

// Remove has nothing to undo: Apply never changes anything here.
func (linuxRedirector) Remove() error { return nil }

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
