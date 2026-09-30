package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/config"
)

// newTestKeypair generates a fresh ed25519 keypair for each test so tests never
// depend on the embedded PublicKey and cannot interfere with each other.
func newTestKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test keypair: %v", err)
	}
	return pub, priv
}

func writeTempBinary(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "testbinary")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("write temp binary: %v", err)
	}
	return path
}

// TestVerifySignatureBytes_Valid signs binary bytes with a test key and confirms
// that verifySignatureBytes accepts the signature when given the matching public key.
func TestVerifySignatureBytes_Valid(t *testing.T) {
	pub, priv := newTestKeypair(t)
	data := []byte("fake release binary content")
	sig := ed25519.Sign(priv, data)

	if err := verifySignatureBytes(data, sig, pub); err != nil {
		t.Errorf("expected valid signature to pass, got: %v", err)
	}
}

// TestVerifySignatureBytes_CorruptedSignature confirms that a single-byte
// corruption in the signature is detected and rejected.
func TestVerifySignatureBytes_CorruptedSignature(t *testing.T) {
	pub, priv := newTestKeypair(t)
	data := []byte("fake release binary content")
	sig := ed25519.Sign(priv, data)

	// Flip one byte in the signature
	corrupted := make([]byte, len(sig))
	copy(corrupted, sig)
	corrupted[0] ^= 0xff

	if err := verifySignatureBytes(data, corrupted, pub); err == nil {
		t.Error("expected corrupted signature to be rejected, got nil error")
	}
}

// TestVerifySignatureBytes_WrongKey signs with key A and verifies with key B —
// the signature must be rejected.
func TestVerifySignatureBytes_WrongKey(t *testing.T) {
	_, privA := newTestKeypair(t)
	pubB, _ := newTestKeypair(t)

	data := []byte("fake release binary content")
	sig := ed25519.Sign(privA, data)

	if err := verifySignatureBytes(data, sig, pubB); err == nil {
		t.Error("expected signature from a different key to be rejected, got nil error")
	}
}

// TestVerifySignatureBytes_TamperedBinary signs original bytes but verifies
// against modified bytes — rejects because content changed after signing.
func TestVerifySignatureBytes_TamperedBinary(t *testing.T) {
	pub, priv := newTestKeypair(t)
	original := []byte("original binary")
	sig := ed25519.Sign(priv, original)

	tampered := []byte("tampered binary!")
	if err := verifySignatureBytes(tampered, sig, pub); err == nil {
		t.Error("expected tampered binary to be rejected, got nil error")
	}
}

// TestVerifySignature_EmptySigAssetPath confirms fail-closed: an empty
// sigAssetPath is rejected without making any network call.
func TestVerifySignature_EmptySigAssetPath(t *testing.T) {
	pub, _ := newTestKeypair(t)
	binaryPath := writeTempBinary(t, []byte("binary"))

	err := verifySignature(context.Background(), &config.Config{}, binaryPath, "", pub)
	if err == nil {
		t.Error("expected empty sigAssetPath to return error (fail closed), got nil")
	}
}

// TestVerifySignature_NonOKStatus confirms a non-200 response from the
// signature-download endpoint is treated as an error.
func TestVerifySignature_NonOKStatus(t *testing.T) {
	pub, _ := newTestKeypair(t)
	binaryPath := writeTempBinary(t, []byte("binary"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cfg := &config.Config{SupabaseURL: srv.URL, SupabaseKey: "test-key"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := verifySignature(ctx, cfg, binaryPath, "v1.0.0/binary.sig", pub)
	if err == nil {
		t.Error("expected error for non-200 signature download status, got nil")
	}
}

// TestVerifySignature_MalformedBase64 confirms a signature body that isn't
// valid base64 is rejected before attempting ed25519 verification.
func TestVerifySignature_MalformedBase64(t *testing.T) {
	pub, _ := newTestKeypair(t)
	binaryPath := writeTempBinary(t, []byte("binary"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-valid-base64!!!"))
	}))
	defer srv.Close()

	cfg := &config.Config{SupabaseURL: srv.URL, SupabaseKey: "test-key"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := verifySignature(ctx, cfg, binaryPath, "v1.0.0/binary.sig", pub)
	if err == nil || !strings.Contains(err.Error(), "decode signature") {
		t.Errorf("err = %v, want a signature-decode error", err)
	}
}

// TestVerifySignature_FullRoundTrip exercises verifySignature end-to-end: a
// fake Supabase Storage server serves a real ed25519 signature over the
// staged binary's actual on-disk bytes, and verification must succeed.
func TestVerifySignature_FullRoundTrip(t *testing.T) {
	pub, priv := newTestKeypair(t)
	content := []byte("fake sentinelgo release binary content")
	binaryPath := writeTempBinary(t, content)

	sig := ed25519.Sign(priv, content)
	encoded := base64.StdEncoding.EncodeToString(sig)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(encoded + "\n"))
	}))
	defer srv.Close()

	cfg := &config.Config{SupabaseURL: srv.URL, SupabaseKey: "test-key"}
	cfg.SetTokens("test-jwt", "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := verifySignature(ctx, cfg, binaryPath, "v1.0.0/binary.sig", pub); err != nil {
		t.Errorf("expected a valid signature to verify successfully, got: %v", err)
	}
}

// TestSignTool_RoundTrip exercises the full sign → verify round-trip using the
// same logic the scripts/sign tool uses (ed25519.Sign + base64 encode) and
// verifySignatureBytes. This confirms the wire format is consistent end-to-end.
func TestSignTool_RoundTrip(t *testing.T) {
	pub, priv := newTestKeypair(t)
	binaryData := []byte("sentinelgo-linux-amd64 fake binary v1.2.3")

	// scripts/sign writes: base64(ed25519.Sign(priv, data)) + "\n"
	sigBytes := ed25519.Sign(priv, binaryData)
	encoded := base64.StdEncoding.EncodeToString(sigBytes) + "\n"

	// Agent decodes: base64 → raw bytes → ed25519.Verify
	decoded, err := base64.StdEncoding.DecodeString(encoded[:len(encoded)-1])
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	if err := verifySignatureBytes(binaryData, decoded, pub); err != nil {
		t.Errorf("round-trip verification failed: %v", err)
	}
}
