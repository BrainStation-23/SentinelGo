//go:build linux

package certificates

import (
	"context"
	"os"
	"path/filepath"
)

// certDir is where Debian/RHEL-family distributions alike keep the system
// trust store as individual PEM files (plus a combined bundle, and
// hash-named symlinks to the same files — see dedupeCertificates).
const certDir = "/etc/ssl/certs"

// platformCertificates parses /etc/ssl/certs directly with crypto/x509 — no
// subprocess needed at all, exactly the case
// docs/telemetry/03-collection-matrix.md calls out ("parse /etc/ssl/certs
// with crypto/x509").
func platformCertificates(_ context.Context) signal {
	entries, err := os.ReadDir(certDir)
	if err != nil {
		return signal{Warnings: []string{"/etc/ssl/certs unreadable"}, Err: err}
	}

	var certs []Certificate
	var readErrors int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// #nosec G304 -- certDir is a fixed constant, entry.Name() is a
		// directory listing from that same fixed path, not user input.
		data, readErr := os.ReadFile(filepath.Join(certDir, entry.Name()))
		if readErr != nil {
			readErrors++
			continue
		}
		certs = append(certs, parsePEMCertificates(data, certDir+"/"+entry.Name())...)
	}

	sig := signal{Certificates: dedupeCertificates(certs), Source: "file:" + certDir}
	if readErrors > 0 {
		sig.Warnings = append(sig.Warnings, "some files in /etc/ssl/certs could not be read")
	}
	return sig
}
