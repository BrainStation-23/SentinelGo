//go:build linux

package epm

import (
	"fmt"
	"os/exec"
	"strings"
)

// VerifyPackageSignature checks whether path is owned by a package managed
// by the system's package manager (dpkg or rpm), verifies that package's
// installed files still match what was recorded at install time, and
// returns a publisher-like identity string (the Debian Maintainer field or
// the RPM Vendor field) for use as ElevationRequest.Publisher.
//
// There is no single cross-distribution equivalent of Windows' Authenticode
// or macOS's codesign, and golang.org/x/sys does not wrap any package-manager
// library (nor would binding libapt/librpm directly be possible without cgo
// — CLAUDE.md's hard no-cgo rule). Shelling out to `dpkg`/`rpm` — the
// system's own, already-installed package tools — is the sanctioned
// equivalent.
//
// An error return means the file is not owned by a known package, or the
// package's files have been altered since install; callers should treat that
// as "no publisher identity available" rather than aborting the whole
// elevation request — hash-based or path-based rules can still match.
func VerifyPackageSignature(path string) (publisher string, err error) {
	if pkg, ownErr := dpkgOwner(path); ownErr == nil {
		if verifyErr := dpkgVerify(pkg); verifyErr != nil {
			return "", verifyErr
		}
		return dpkgMaintainer(pkg)
	}

	if pkg, ownErr := rpmOwner(path); ownErr == nil {
		if verifyErr := rpmVerify(pkg); verifyErr != nil {
			return "", verifyErr
		}
		return rpmVendor(pkg)
	}

	return "", fmt.Errorf("%s is not owned by a known package (dpkg/rpm)", path)
}

func dpkgOwner(path string) (string, error) {
	out, err := exec.Command("dpkg", "-S", path).Output()
	if err != nil {
		return "", fmt.Errorf("dpkg -S: %w", err)
	}
	return parseDpkgOwner(string(out))
}

// parseDpkgOwner extracts the package name from `dpkg -S`'s output, which
// looks like "package-name: /path/to/file" (dpkg -S can list more than one
// package for a shared path; we take the first line).
func parseDpkgOwner(output string) (string, error) {
	line := strings.TrimSpace(output)
	if idx := strings.IndexByte(line, '\n'); idx >= 0 {
		line = line[:idx]
	}
	pkg, _, ok := strings.Cut(line, ":")
	if !ok || strings.TrimSpace(pkg) == "" {
		return "", fmt.Errorf("unexpected dpkg -S output: %q", line)
	}
	return strings.TrimSpace(pkg), nil
}

func dpkgVerify(pkg string) error {
	// dpkg -V exits non-zero and prints a per-file diff marker line for each
	// altered file when verification fails; exit 0 (empty output) means every
	// tracked file still matches what was recorded at install time.
	out, err := exec.Command("dpkg", "-V", pkg).CombinedOutput()
	if err != nil {
		return fmt.Errorf("dpkg -V %s: package verification failed: %w (%s)", pkg, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func dpkgMaintainer(pkg string) (string, error) {
	out, err := exec.Command("dpkg-query", "-W", "-f=${Maintainer}", pkg).Output()
	if err != nil {
		return "", fmt.Errorf("dpkg-query maintainer: %w", err)
	}
	maintainer := strings.TrimSpace(string(out))
	if maintainer == "" {
		return "", fmt.Errorf("empty maintainer field for package %s", pkg)
	}
	return maintainer, nil
}

func rpmOwner(path string) (string, error) {
	out, err := exec.Command("rpm", "-qf", path).Output()
	if err != nil {
		return "", fmt.Errorf("rpm -qf: %w", err)
	}
	pkg := strings.TrimSpace(string(out))
	if pkg == "" {
		return "", fmt.Errorf("empty rpm -qf output")
	}
	return pkg, nil
}

func rpmVerify(pkg string) error {
	// rpm -V exits non-zero and prints per-file markers when verification
	// fails; exit 0 (empty output) means everything matches.
	out, err := exec.Command("rpm", "-V", pkg).CombinedOutput()
	if err != nil {
		return fmt.Errorf("rpm -V %s: package verification failed: %w (%s)", pkg, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func rpmVendor(pkg string) (string, error) {
	out, err := exec.Command("rpm", "-q", "--qf", "%{VENDOR}", pkg).Output()
	if err != nil {
		return "", fmt.Errorf("rpm -q vendor: %w", err)
	}
	vendor := strings.TrimSpace(string(out))
	if vendor == "" || vendor == "(none)" {
		return "", fmt.Errorf("empty/unset vendor field for package %s", pkg)
	}
	return vendor, nil
}
