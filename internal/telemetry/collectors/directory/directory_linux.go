//go:build linux

package directory

import (
	"context"
	"os"
	"os/exec"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

// platformCapability reports whether this host has any mechanism at all to
// determine directory join state. Absence of both realmd and sssd is common
// on plain Linux servers and does NOT mean "not joined" — it means this host
// cannot be asked, which is CapUnsupported, not a confident false.
func platformCapability(context.Context) tel.CapabilityState {
	if _, err := exec.LookPath("realm"); err == nil {
		return tel.CapSupported
	}
	if _, err := os.Stat("/etc/sssd/sssd.conf"); err == nil {
		return tel.CapSupported
	}
	return tel.CapUnsupported
}

// platformSignal prefers `realm list`, which reports a confirmed live join,
// falling back to sssd's static configuration when realmd tooling is not
// installed — the two mechanisms docs/telemetry/03-collection-matrix.md
// documents for Linux. Entra ID has no Linux concept and stays untouched.
func platformSignal(ctx context.Context) (sig signal) {
	if _, err := exec.LookPath("realm"); err == nil {
		out, _, err := shared.RunCommandOutputContext(ctx, "realm", "list")
		if err != nil {
			sig.Warnings = append(sig.Warnings, "realm list failed to run")
			sig.ADErr = err
			return sig
		}
		joined, domain := parseRealmList(out)
		sig.DomainJoined = &joined
		sig.Domain = domain
		sig.Source = "exec:realm"
		return sig
	}

	if content, err := shared.ReadFileContent("/etc/sssd/sssd.conf"); err == nil {
		joined, domain := parseSSSDConfig(content)
		sig.DomainJoined = &joined
		sig.Domain = domain
		sig.Source = "file:/etc/sssd/sssd.conf"
		return sig
	} else if _, statErr := os.Stat("/etc/sssd/sssd.conf"); statErr == nil {
		// The file exists (platformCapability saw it) but could not be read —
		// almost certainly a permission problem. Surface that rather than
		// silently reporting "not joined".
		sig.Warnings = append(sig.Warnings, "sssd.conf unreadable")
		sig.ADErr = err
		return sig
	}

	// platformCapability already gates the "neither mechanism exists" case to
	// CapUnsupported, so Collect is not invoked and this line is not reached in
	// production. Kept as a defensive, honest fallback (nil, not false) rather
	// than assuming that invariant always holds.
	sig.Warnings = append(sig.Warnings, "no directory-join tooling found (realm, sssd)")
	sig.ADErr = tel.ErrNotSupported
	return sig
}
