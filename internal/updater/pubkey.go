package updater

import "crypto/ed25519"

// PublicKey is the ed25519 public key used to verify release binary signatures.
// The matching private key lives in GitHub Actions secret SENTINELGO_SIGNING_KEY.
// All release binaries are signed with this key; the updater rejects any binary
// whose .sig file does not pass ed25519.Verify against this key (fail closed).
//
// To rotate: run `go run ./scripts/keygen`, update this literal and the GitHub
// secret, then tag a new release. The old agent will accept the new binary only
// if it was signed with the OLD key — rotate on a minor/major version bump so
// users can stage the key-rotation release deliberately.
var PublicKey = ed25519.PublicKey{
	0x62, 0x19, 0xa3, 0x31, 0x1d, 0xc9, 0x4c, 0x07,
	0x60, 0x48, 0xb1, 0xd4, 0x46, 0xd5, 0x2b, 0x36,
	0xe8, 0xa1, 0xd2, 0x6c, 0xcb, 0x67, 0xcf, 0x2f,
	0x25, 0x78, 0x54, 0x28, 0xdb, 0xda, 0xee, 0x7e,
}
