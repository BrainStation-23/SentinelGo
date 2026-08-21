//go:build darwin

package certificates

import (
	"context"

	"sentinelgo/internal/osinfo/shared"
)

// platformCertificates reads the System keychain via `security
// find-certificate -a -p`, the matrix-documented mechanism, which dumps
// every certificate as concatenated PEM text — parsed with the same
// crypto/x509 logic the Linux platform file uses, rather than a second
// bespoke parser.
func platformCertificates(ctx context.Context) signal {
	out, err := shared.RunCommandContext(ctx, "security", "find-certificate", "-a", "-p",
		"/Library/Keychains/System.keychain")
	if err != nil {
		return signal{Warnings: []string{"security find-certificate failed to run"}, Err: err}
	}

	certs := dedupeCertificates(parsePEMCertificates([]byte(out), "system"))
	return signal{Certificates: certs, Source: "exec:security"}
}
