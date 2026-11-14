// Package macsign prepares the macOS agent binary to be started by launchd.
//
// Release builds may carry a certificate signature from CI (#352): an
// internal-CA identity today, Developer ID later. MDM profiles (Full Disk
// Access, notifications) pin the agent by that signature, so it must survive
// installs and self-updates. Builds without one (no signing certificate
// configured in CI, or a local build) are signed ad-hoc on the machine as
// before, so launchd and Gatekeeper accept them.
package macsign

import (
	"os/exec"
	"strings"

	"sentinelgo/internal/binpath"
)

// PrepareBinary removes the download quarantine flag from path, signs it
// ad-hoc unless it already has a valid certificate signature, and registers
// it with Gatekeeper. Every step is best effort, as before: a failure leaves
// the binary as it was. It reports whether the certificate signature was
// kept.
func PrepareBinary(path string) (keptCertSignature bool) {
	// #nosec G204 - binpath.Resolve returns a fixed, verified absolute path or the literal name; not attacker input
	_ = exec.Command(binpath.Resolve("xattr"), "-d", "com.apple.quarantine", path).Run()
	keptCertSignature = certSigned(path)
	if !keptCertSignature {
		// An ad-hoc re-sign replaces any signature, so it only runs on
		// binaries that have none worth keeping.
		// #nosec G204 - binpath.Resolve returns a fixed, verified absolute path or the literal name; not attacker input
		_ = exec.Command(binpath.Resolve("codesign"), "--force", "--sign", "-", path).Run()
	}
	// #nosec G204 - binpath.Resolve returns a fixed, verified absolute path or the literal name; not attacker input
	_ = exec.Command(binpath.Resolve("spctl"), "--add", path).Run()
	return keptCertSignature
}

// certSigned reports whether path has a certificate signature that still
// verifies. A signature broken by a modified file is not kept: re-signing
// ad-hoc is what lets it start, as it did before release signing.
func certSigned(path string) bool {
	// codesign -d writes the signature details to stderr.
	// #nosec G204 - binpath.Resolve returns a fixed, verified absolute path or the literal name; not attacker input
	out, _ := exec.Command(binpath.Resolve("codesign"), "-dv", "--verbose=2", path).CombinedOutput()
	if !hasAuthority(string(out)) {
		return false
	}
	// #nosec G204 - binpath.Resolve returns a fixed, verified absolute path or the literal name; not attacker input
	return exec.Command(binpath.Resolve("codesign"), "--verify", "--strict", path).Run() == nil
}

// hasAuthority reports whether `codesign -dv --verbose=2` output names a
// signing certificate. Ad-hoc and linker signatures (the Go linker signs
// darwin/arm64 builds) have no Authority= line; unsigned files have no
// signature at all.
func hasAuthority(codesignOutput string) bool {
	for _, line := range strings.Split(codesignOutput, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Authority=") {
			return true
		}
	}
	return false
}
