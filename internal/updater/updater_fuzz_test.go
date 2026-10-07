package updater

// Fuzz targets for the updater's trust decisions. The release RPC supplies the
// version string that decides whether a binary is installed, and the signature
// check is the last gate before that binary runs as root/SYSTEM. Both must
// handle arbitrary input without panicking and must fail closed.
//
// The seed corpus below runs as an ordinary unit test under `go test ./...`.
// To actually fuzz one target:
//
//	go test -run='^$' -fuzz='^FuzzParseSemver$' -fuzztime=1m ./internal/updater/

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
)

var versionSeeds = []string{
	"v2.1.6", "2.1.5", "V2.1.6", "v2.1.6-rc1", "v2.1.6+build.5", "v2.2", "v2",
	"dev", "1.2.3.4", "", "v", "V", "vV1.0.0", "1..2", ".1.2", "1.2.",
	"99999999999999999999.0.0", "9223372036854775807.0.0", "-1.0.0", "v-1",
	"  v1.2.3  ", "\tv1.2.3\n", "1.2.3-", "+1.2.3", "01.02.03", "1.2.3\x00",
	"１.２.３", strings.Repeat("9", 400),
}

func FuzzParseSemver(f *testing.F) {
	for _, s := range versionSeeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		v, err := parseSemver(s)
		if err != nil {
			return
		}
		if v.major < 0 || v.minor < 0 || v.patch < 0 {
			t.Fatalf("parseSemver(%q) = %+v: negative component accepted", s, v)
		}
		// The canonical form must re-parse to the same value.
		canon := fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
		again, err := parseSemver(canon)
		if err != nil || again != v {
			t.Fatalf("parseSemver(%q) = %+v, but canonical %q re-parses to %+v, %v", s, v, canon, again, err)
		}
	})
}

func FuzzCompareVersions(f *testing.F) {
	for i, a := range versionSeeds {
		f.Add(a, versionSeeds[(i+1)%len(versionSeeds)])
	}
	f.Add("v2.1.5", "v2.1.5")
	f.Add("v2.1.6-rc1", "v2.1.6")

	f.Fuzz(func(t *testing.T, a, b string) {
		va, errA := parseSemver(a)
		vb, errB := parseSemver(b)
		if errA == nil && errB == nil {
			if va.compare(vb) != -vb.compare(va) {
				t.Fatalf("compare not antisymmetric for %q (%+v) vs %q (%+v)", a, va, b, vb)
			}
			if va.compare(va) != 0 {
				t.Fatalf("compare(%q, itself) != 0", a)
			}
		}

		if newer, err := isNewerVersion(a, a); err == nil && newer {
			t.Fatalf("isNewerVersion(%q, %q) = true: a version must never be newer than itself", a, a)
		}
		ab, errAB := isNewerVersion(a, b)
		ba, errBA := isNewerVersion(b, a)
		if errAB == nil && errBA == nil && ab && ba {
			t.Fatalf("isNewerVersion is true in both directions for %q and %q", a, b)
		}
		if (errAB != nil) != (errA != nil || errB != nil) {
			t.Fatalf("isNewerVersion(%q, %q) error = %v, but parse errors are %v / %v", a, b, errAB, errA, errB)
		}
	})
}

// fuzzSigningKey is a fixed test keypair, so the fuzzer can also check that a
// valid signature is accepted and that any other signature is rejected.
var fuzzSigningKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5a}, ed25519.SeedSize))

func FuzzVerifySignatureBytes(f *testing.F) {
	binary := []byte("sentinelgo release binary")
	valid := ed25519.Sign(fuzzSigningKey, binary)
	flipped := bytes.Clone(valid)
	flipped[0] ^= 0x01

	f.Add(binary, valid)
	f.Add(binary, flipped)
	f.Add(binary, []byte{})
	f.Add(binary, make([]byte, ed25519.SignatureSize))
	f.Add(binary, make([]byte, ed25519.SignatureSize-1))
	f.Add(binary, make([]byte, ed25519.SignatureSize+1))
	f.Add([]byte{}, valid)
	f.Add([]byte(nil), []byte(nil))

	testPub, ok := fuzzSigningKey.Public().(ed25519.PublicKey)
	if !ok {
		f.Fatal("test key has no ed25519 public key")
	}

	f.Fuzz(func(t *testing.T, bin, sig []byte) {
		// Nobody but the release pipeline holds the production private key, so
		// fuzzed input must never verify against it.
		if err := verifySignatureBytes(bin, sig, PublicKey); err == nil {
			t.Fatalf("fuzzed signature verified against the production key: bin=%x sig=%x", bin, sig)
		}

		// Against the test key, exactly the genuine signature is accepted:
		// Go's ed25519 rejects malleable (non-canonical) signatures, so any
		// other byte string must fail.
		genuine := ed25519.Sign(fuzzSigningKey, bin)
		if err := verifySignatureBytes(bin, genuine, testPub); err != nil {
			t.Fatalf("genuine signature rejected: %v", err)
		}
		if !bytes.Equal(sig, genuine) {
			if err := verifySignatureBytes(bin, sig, testPub); err == nil {
				t.Fatalf("non-genuine signature accepted: bin=%x sig=%x", bin, sig)
			}
		}
	})
}

// TestPublicKeyLength guards the embedded release key: ed25519.Verify panics
// on a key of the wrong length, so a bad edit to pubkey.go would crash every
// agent at its next update check instead of failing here.
func TestPublicKeyLength(t *testing.T) {
	if len(PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("len(PublicKey) = %d, want %d", len(PublicKey), ed25519.PublicKeySize)
	}
}
