//go:build windows

package epm

import (
	"os"
	"strings"
	"testing"
)

// TestVerifyAuthenticode_RealSignedSystemBinary exercises leafCertificateName
// against a real, multi-certificate-chain Authenticode signature (leaf +
// intermediate + root CA all embedded) rather than a synthetic fixture — the
// only reliable way to validate the leaf-vs-CA selection heuristic without
// hand-rolling a signed test binary. explorer.exe is present and signed on
// every mainstream Windows desktop install; on a minimal/Server Core image
// where it's absent, the test skips rather than failing.
func TestVerifyAuthenticode_RealSignedSystemBinary(t *testing.T) {
	const path = `C:\Windows\explorer.exe`
	if _, err := os.Stat(path); err != nil {
		t.Skipf("explorer.exe not present on this system: %v", err)
	}

	publisher, err := VerifyAuthenticode(path)
	if err != nil {
		t.Fatalf("VerifyAuthenticode(%s): %v", path, err)
	}
	if publisher == "" {
		t.Fatal("expected a non-empty publisher for a signed system binary")
	}
	// Must resolve to the leaf (end-entity) certificate's name, not an
	// intermediate/root CA name such as "Microsoft Root Certificate
	// Authority" or "Microsoft Code Signing PCA" — this is exactly the
	// distinction leafCertificateName exists to make.
	if strings.Contains(publisher, "Root") || strings.Contains(publisher, " CA") || strings.Contains(publisher, "Certificate Authority") {
		t.Errorf("publisher = %q looks like a CA certificate, not the leaf signer", publisher)
	}
	t.Logf("resolved publisher: %q", publisher)
}
