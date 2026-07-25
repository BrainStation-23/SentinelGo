//go:build darwin

package epm

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// VerifyCodeSignature checks path's code signature via the `codesign` CLI
// and, if valid, returns the signer's identity (the first "Authority="
// entry, which is the leaf/signing certificate) for use as
// ElevationRequest.Publisher.
//
// golang.org/x/sys does not wrap Security.framework's SecCodeCheckValidity
// or SecCertificateCopySubjectSummary, and binding them directly would
// require cgo (CLAUDE.md's hard no-cgo rule). Shelling out to `codesign` —
// Apple's own, officially supported CLI for exactly this check — is the
// sanctioned equivalent: the same subprocess-to-OS-CLI pattern this codebase
// already uses for `journalctl`/`log show` on Linux/macOS log collection.
//
// An error return means the file is unsigned or its signature does not
// verify; callers should treat that as "no publisher identity available"
// rather than aborting the whole elevation request outright — hash-based or
// path-based rules can still match an unsigned binary.
func VerifyCodeSignature(path string) (publisher string, err error) {
	if err := verifyCodesign(path); err != nil {
		return "", err
	}

	name, nameErr := codesignAuthority(path)
	if nameErr != nil {
		// The signature verified, but we couldn't parse a signer identity out
		// of codesign's diagnostic output. Report success with no name rather
		// than failing the whole check: the caller still knows the binary is
		// genuinely signed.
		return "", nil
	}
	return name, nil
}

// verifyCodesign checks that path's signature is valid and its on-disk
// content matches what was signed (including nested/embedded code for app
// bundles).
func verifyCodesign(path string) error {
	cmd := exec.Command("codesign", "--verify", "--deep", "--strict", path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("codesign verification failed: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// codesignAuthority extracts the first "Authority=" line from `codesign -d
// --verbose=4`'s diagnostic output, which is the signing (leaf) certificate's
// identity.
func codesignAuthority(path string) (string, error) {
	cmd := exec.Command("codesign", "-d", "--verbose=4", path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// codesign -d exits 0 for a signed binary regardless of whether the
	// signature is currently valid (that check already happened in
	// verifyCodesign); we only need the diagnostic text here.
	_ = cmd.Run()
	return firstAuthority(stderr.String())
}

func firstAuthority(codesignOutput string) (string, error) {
	scanner := bufio.NewScanner(strings.NewReader(codesignOutput))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if after, ok := strings.CutPrefix(line, "Authority="); ok {
			return after, nil
		}
	}
	return "", fmt.Errorf("no Authority= line found in codesign output")
}
