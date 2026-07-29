package epm

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"sentinelgo/internal/config"
)

// TestSignatureModeMatchesConfigConstants mirrors
// tokentype_test.go's TestTokenTypeMatchesConfigConstants: internal/config
// validates epm_policy_signature_mode against its own string constants
// rather than importing internal/epm, so the two sets must agree.
func TestSignatureModeMatchesConfigConstants(t *testing.T) {
	tests := []struct{ epm, config string }{
		{SignatureModeOff, config.EPMSignatureModeOff},
		{SignatureModeWarn, config.EPMSignatureModeWarn},
		{SignatureModeRequire, config.EPMSignatureModeRequire},
	}
	for _, tc := range tests {
		if tc.epm != tc.config {
			t.Errorf("epm mode %q != config constant %q", tc.epm, tc.config)
		}
	}
}

func TestConfigDefaultSignatureModeIsValid(t *testing.T) {
	def := (&config.Config{}).GetEPMPolicySignatureMode()
	switch def {
	case SignatureModeOff, SignatureModeWarn, SignatureModeRequire:
	default:
		t.Fatalf("config default signature mode %q is not a value epm recognises", def)
	}
	if def != SignatureModeWarn {
		t.Errorf("config default = %q, want %q — every bundle must be checked by default, "+
			"without yet requiring signing from a backend that hasn't adopted it", def, SignatureModeWarn)
	}
}

func newTestBundleKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func signTestBundle(t *testing.T, keyID string, priv ed25519.PrivateKey, payload []byte) *SignedBundle {
	t.Helper()
	sig := ed25519.Sign(priv, payload)
	return &SignedBundle{
		Payload:   json.RawMessage(payload),
		Algorithm: "ed25519",
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
}

// withTestSigningKey installs pub under keyID in PolicySigningKeys for the
// duration of the test, restoring the original (real, presumably empty) map
// afterward — VerifyBundle reads the package-level PolicySigningKeys
// directly, matching internal/updater's PublicKey-swap-free test pattern
// only insofar as it is a map here instead of a single var; the swap-and-
// restore idiom is the same one internal/config/config_test.go and others in
// this codebase already use for package-level state.
func withTestSigningKey(t *testing.T, keyID string, pub ed25519.PublicKey) {
	t.Helper()
	orig := PolicySigningKeys
	PolicySigningKeys = map[string]ed25519.PublicKey{keyID: pub}
	t.Cleanup(func() { PolicySigningKeys = orig })
}

func TestVerifyBundle_ValidSignature(t *testing.T) {
	pub, priv := newTestBundleKeypair(t)
	withTestSigningKey(t, "key-1", pub)

	sb := signTestBundle(t, "key-1", priv, []byte(`{"bundle_id":"b1"}`))
	status, err := VerifyBundle(sb, SignatureModeRequire)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if status != SigVerified {
		t.Errorf("status = %s, want verified", status)
	}
}

func TestVerifyBundle_TamperedPayloadFails(t *testing.T) {
	pub, priv := newTestBundleKeypair(t)
	withTestSigningKey(t, "key-1", pub)

	sb := signTestBundle(t, "key-1", priv, []byte(`{"bundle_id":"b1"}`))
	sb.Payload = json.RawMessage(`{"bundle_id":"b1-tampered"}`) // one byte changed

	status, err := VerifyBundle(sb, SignatureModeRequire)
	if err == nil {
		t.Fatal("expected an error for a tampered payload under \"require\"")
	}
	if status != SigFailed {
		t.Errorf("status = %s, want failed", status)
	}
}

func TestVerifyBundle_WrongKeyFails(t *testing.T) {
	_, wrongPriv := newTestBundleKeypair(t)
	rightPub, _ := newTestBundleKeypair(t)
	withTestSigningKey(t, "key-1", rightPub)

	sb := signTestBundle(t, "key-1", wrongPriv, []byte(`{"bundle_id":"b1"}`))
	status, err := VerifyBundle(sb, SignatureModeRequire)
	if err == nil {
		t.Fatal("expected an error when signed with the wrong key")
	}
	if status != SigFailed {
		t.Errorf("status = %s, want failed", status)
	}
}

func TestVerifyBundle_ModeOff_SkipsVerificationEntirely(t *testing.T) {
	// No key installed at all — an "off" bundle must still succeed.
	sb := &SignedBundle{Payload: json.RawMessage(`{"bundle_id":"b1"}`), Signature: "not-even-valid-base64!!!"}
	status, err := VerifyBundle(sb, SignatureModeOff)
	if err != nil {
		t.Fatalf("VerifyBundle with mode=off: %v", err)
	}
	if status != SigUnverified {
		t.Errorf("status = %s, want unverified", status)
	}
}

func TestVerifyBundle_ModeWarn_FailsSoftly(t *testing.T) {
	pub, _ := newTestBundleKeypair(t)
	withTestSigningKey(t, "key-1", pub)

	// No matching key was used to sign this — a garbage signature.
	sb := &SignedBundle{
		Payload:   json.RawMessage(`{"bundle_id":"b1"}`),
		KeyID:     "key-1",
		Signature: base64.StdEncoding.EncodeToString([]byte("not a real signature, wrong length")),
	}
	status, err := VerifyBundle(sb, SignatureModeWarn)
	if err != nil {
		t.Fatalf("VerifyBundle with mode=warn must never return an error, got %v", err)
	}
	if status != SigFailed {
		t.Errorf("status = %s, want failed (recorded, but not rejected)", status)
	}
}

func TestVerifyBundle_EmptyModeDefaultsToWarn(t *testing.T) {
	pub, priv := newTestBundleKeypair(t)
	withTestSigningKey(t, "key-1", pub)
	sb := signTestBundle(t, "key-1", priv, []byte(`{"bundle_id":"b1"}`))

	status, err := VerifyBundle(sb, "")
	if err != nil {
		t.Fatalf("VerifyBundle with mode=\"\": %v", err)
	}
	if status != SigVerified {
		t.Errorf("status = %s, want verified", status)
	}
}

func TestVerifyBundle_NoKeysConfigured(t *testing.T) {
	orig := PolicySigningKeys
	PolicySigningKeys = map[string]ed25519.PublicKey{}
	t.Cleanup(func() { PolicySigningKeys = orig })

	sb := &SignedBundle{
		Payload:   json.RawMessage(`{"bundle_id":"b1"}`),
		Signature: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	}
	status, err := VerifyBundle(sb, SignatureModeRequire)
	if err == nil {
		t.Fatal("expected an error when no signing keys are configured under \"require\"")
	}
	if status != SigFailed {
		t.Errorf("status = %s, want failed", status)
	}
}

func TestVerifyBundle_MalformedBase64Signature(t *testing.T) {
	pub, _ := newTestBundleKeypair(t)
	withTestSigningKey(t, "key-1", pub)

	sb := &SignedBundle{Payload: json.RawMessage(`{"bundle_id":"b1"}`), KeyID: "key-1", Signature: "!!!not base64!!!"}
	if _, err := VerifyBundle(sb, SignatureModeRequire); err == nil {
		t.Fatal("expected an error for malformed base64")
	}
}

func TestSignedBundle_DecodePayload(t *testing.T) {
	bundle := PolicyBundle{BundleID: "b1", Generation: 5, Mode: "full"}
	payload, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	sb := &SignedBundle{Payload: payload}

	got, err := sb.DecodePayload()
	if err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if got.BundleID != "b1" || got.Generation != 5 || got.Mode != "full" {
		t.Errorf("decoded = %+v, want the original bundle", got)
	}
}
