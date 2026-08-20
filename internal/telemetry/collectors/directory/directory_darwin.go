//go:build darwin

package directory

import (
	"context"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

// platformCapability reports CapSupported unconditionally: dsconfigad ships
// standard on every supported macOS target.
func platformCapability(context.Context) tel.CapabilityState {
	return tel.CapSupported
}

// platformSignal reads Active Directory join state via `dsconfigad -show`.
// Entra ID has no macOS concept and stays untouched. RunCommandOutputContext
// is used because an unjoined Mac may return a non-zero exit alongside
// minimal or no output, and the caller must still see that empty output
// rather than have it discarded as a command failure.
func platformSignal(ctx context.Context) (sig signal) {
	out, _, err := shared.RunCommandOutputContext(ctx, "dsconfigad", "-show")
	if err != nil {
		sig.Warnings = append(sig.Warnings, "dsconfigad -show failed to run")
		sig.ADErr = err
		return sig
	}
	joined, domain := parseDsconfigad(out)
	sig.DomainJoined = &joined
	sig.Domain = domain
	sig.Source = "exec:dsconfigad"
	return sig
}
