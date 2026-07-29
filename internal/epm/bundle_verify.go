package epm

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// SigStatus is the outcome of verifying a SignedBundle against
// PolicySigningKeys, recorded in epm_bundles.sig_status so an operator can
// see, per bundle, whether it was actually checked.
type SigStatus string

const (
	SigVerified   SigStatus = "verified"
	SigUnverified SigStatus = "unverified" // verification mode is "off"
	SigFailed     SigStatus = "failed"
)

// Signature-mode config values (see config.go's EPMPolicySignatureMode
// equivalent — internal/epm intentionally has no dependency on
// internal/config, matching the pattern already established for
// EPMWindowsTokenType/TokenType in tokentype.go; the config package declares
// matching string constants for validation instead of importing this one).
const (
	SignatureModeOff     = "off"
	SignatureModeWarn    = "warn"
	SignatureModeRequire = "require"
)

// VerifyBundle checks sb against PolicySigningKeys according to mode:
//
//   - "off": no cryptographic check at all; always returns (SigUnverified, nil)
//     — bundles apply exactly as if signing did not exist. This is the
//     escape hatch that keeps an existing, unsigned backend working —
//     signature verification must never be a hard requirement for a
//     deployment that has not adopted it.
//   - "warn": verifies, but a failure is reported (SigFailed, nil — no
//     error) rather than rejecting the bundle. The intended default for the
//     migration period: every bundle is checked and every failure is
//     visible (epm_bundles.sig_status, logs), but nothing breaks for a
//     backend that has not started signing yet.
//   - "require": verifies and fails closed — a bad or missing signature
//     returns a non-nil error, and BundleManager.Apply must reject the
//     bundle outright.
//
// Verification is always against sb.Payload's raw bytes exactly as received
// — see bundle.go's SignedBundle doc comment for why that, not a
// re-marshalled struct, is what gets signed and checked.
func VerifyBundle(sb *SignedBundle, mode string) (SigStatus, error) {
	if mode == "" {
		mode = SignatureModeWarn
	}
	if mode == SignatureModeOff {
		return SigUnverified, nil
	}

	ok, verifyErr := verifyBundleSignature(sb)
	switch {
	case ok:
		return SigVerified, nil
	case mode == SignatureModeRequire:
		return SigFailed, fmt.Errorf("policy bundle signature verification failed: %w", verifyErr)
	default: // "warn"
		return SigFailed, nil
	}
}

// verifyBundleSignature reports whether sb's signature validates against any
// key in PolicySigningKeys — trying the specific KeyID first (the common,
// fast path), then falling back to every known key in case a bundle omits
// KeyID or names one this agent has not been told about yet under a
// different label. Returns a descriptive error on failure for VerifyBundle's
// "require" path to wrap; the error is never surfaced in "warn" mode.
func verifyBundleSignature(sb *SignedBundle) (bool, error) {
	if sb.Algorithm != "" && sb.Algorithm != "ed25519" {
		return false, fmt.Errorf("unsupported signature algorithm %q", sb.Algorithm)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sb.Signature)
	if err != nil {
		return false, fmt.Errorf("decode signature (expected base64): %w", err)
	}
	if len(sb.Payload) == 0 {
		return false, fmt.Errorf("empty payload")
	}

	if key, ok := PolicySigningKeys[sb.KeyID]; ok {
		if ed25519.Verify(key, sb.Payload, sigBytes) {
			return true, nil
		}
		return false, fmt.Errorf("signature does not verify against key %q", sb.KeyID)
	}

	for _, key := range PolicySigningKeys {
		if ed25519.Verify(key, sb.Payload, sigBytes) {
			return true, nil
		}
	}
	if len(PolicySigningKeys) == 0 {
		return false, fmt.Errorf("no policy signing keys configured")
	}
	return false, fmt.Errorf("signature does not verify against any known key (key_id %q)", sb.KeyID)
}
