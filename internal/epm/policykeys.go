package epm

import "crypto/ed25519"

// PolicySigningKeys are the pinned ed25519 public keys trusted to sign policy
// bundles, keyed by the KeyID a SignedBundle names. Multiple keys are
// supported simultaneously so rotation can be staged: publish the new key in
// release N (added here), start signing with it in N+1, retire the old key
// once every fleet agent has updated past N. Mirrors
// internal/updater.PublicKey's rotation doctrine exactly, generalized to a
// map since policy-signing keys (unlike the single release-binary key) are
// expected to rotate per tenant or per environment over time.
//
// Empty until a real signing key exists — no such key has been generated or
// distributed to a backend as part of this work (that requires
// `go run ./scripts/keygen` plus operational key custody this repository
// does not own). With this map empty, VerifyBundle always reports SigFailed
// for any bundle (no key can match), which is the correct, safe default: at
// epm_policy_signature_mode="warn" (the default — see config.go) a bundle
// still applies with the failure logged, so an empty key set does not block
// anyone; at "require" it fails closed. Populate this map (and flip the
// default signature mode) once real keys and a signing backend exist.
var PolicySigningKeys = map[string]ed25519.PublicKey{}
