package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// generateTestCert builds a minimal self-signed certificate for parsing
// tests, so this suite exercises the real crypto/x509 + PEM path rather than
// a hand-built fixture that might not match what a real certificate's ASN.1
// encoding actually looks like.
func generateTestCert(t *testing.T, commonName string) (der []byte, pemBytes []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	pemBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return der, pemBytes
}

func TestCertFromX509(t *testing.T) {
	der, _ := generateTestCert(t, "test.example.com")
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	got := certFromX509(cert, "root")
	if !strings.Contains(got.Subject, "test.example.com") {
		t.Errorf("Subject = %q, want it to contain the common name", got.Subject)
	}
	if got.Thumbprint == "" || len(got.Thumbprint) != 40 {
		t.Errorf("Thumbprint = %q, want a 40-char hex SHA-1", got.Thumbprint)
	}
	if got.NotBefore != "2026-01-01T00:00:00Z" {
		t.Errorf("NotBefore = %q", got.NotBefore)
	}
	if got.NotAfter != "2027-01-01T00:00:00Z" {
		t.Errorf("NotAfter = %q", got.NotAfter)
	}
	if got.Store != "root" {
		t.Errorf("Store = %q, want root", got.Store)
	}
}

// TestCertFromX509_NeverCarriesKeyMaterial is the structural guarantee the
// package doc promises: nothing this collector produces can ever contain
// private key bytes, because certFromX509 only ever reads Subject/Issuer/
// NotBefore/NotAfter/Raw(for the fingerprint) off the parsed certificate —
// never anything from a private key type.
func TestCertFromX509_NeverCarriesKeyMaterial(t *testing.T) {
	der, _ := generateTestCert(t, "no-keys.example.com")
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	got := certFromX509(cert, "my")

	// A PEM-encoded EC/RSA private key always contains this marker text.
	for _, field := range []string{got.Subject, got.Issuer, got.Thumbprint, got.NotBefore, got.NotAfter, got.Store} {
		if strings.Contains(field, "PRIVATE KEY") {
			t.Fatalf("a Certificate field contains private key marker text: %q", field)
		}
	}
}

func TestParsePEMCertificates(t *testing.T) {
	_, pem1 := generateTestCert(t, "one.example.com")
	_, pem2 := generateTestCert(t, "two.example.com")
	blob := append(append([]byte{}, pem1...), pem2...)

	certs := parsePEMCertificates(blob, "test-store")
	if len(certs) != 2 {
		t.Fatalf("got %d certs, want 2: %+v", len(certs), certs)
	}
	if certs[0].Store != "test-store" || certs[1].Store != "test-store" {
		t.Errorf("store not propagated: %+v", certs)
	}
}

func TestParsePEMCertificates_SkipsGarbage(t *testing.T) {
	_, pem1 := generateTestCert(t, "valid.example.com")
	garbage := []byte("-----BEGIN CERTIFICATE-----\nbm90IGEgcmVhbCBjZXJ0\n-----END CERTIFICATE-----\n")
	blob := append(append([]byte{}, garbage...), pem1...)

	certs := parsePEMCertificates(blob, "test-store")
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1 (garbage block must be skipped, not fail the whole blob): %+v", len(certs), certs)
	}
}

func TestParsePEMCertificates_Empty(t *testing.T) {
	if got := parsePEMCertificates([]byte("not pem at all"), "s"); got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

func TestDedupeCertificates(t *testing.T) {
	certs := []Certificate{
		{Thumbprint: "AAAA", Subject: "a"},
		{Thumbprint: "BBBB", Subject: "b"},
		{Thumbprint: "AAAA", Subject: "a-duplicate-via-symlink"},
	}
	got := dedupeCertificates(certs)
	if len(got) != 2 {
		t.Fatalf("got %d certs, want 2: %+v", len(got), got)
	}
	if got[0].Thumbprint != "AAAA" || got[1].Thumbprint != "BBBB" {
		t.Errorf("got %+v", got)
	}
}

func TestParseWindowsCerts_Array(t *testing.T) {
	const sample = `[{"Subject":"CN=test","Issuer":"CN=ca","Thumbprint":"abc123","NotBefore":"2026-01-01T00:00:00","NotAfter":"2027-01-01T00:00:00","Store":"root"}]`
	rows, err := parseWindowsCerts(sample)
	if err != nil {
		t.Fatalf("parseWindowsCerts: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %+v", rows)
	}
	c := rows[0].toCertificate()
	if c.Thumbprint != "ABC123" {
		t.Errorf("Thumbprint = %q, want uppercased ABC123", c.Thumbprint)
	}
}

func TestParseWindowsCerts_Empty(t *testing.T) {
	rows, err := parseWindowsCerts("")
	if err != nil || rows != nil {
		t.Errorf("got (%v, %v), want (nil, nil)", rows, err)
	}
}
