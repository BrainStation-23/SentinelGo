package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

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
