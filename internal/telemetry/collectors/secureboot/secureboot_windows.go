//go:build windows

package secureboot

import (
	"context"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

const (
	secureBootKey   = `HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State`
	secureBootValue = "UEFISecureBootEnabled"
	// windowsMechanism names what was read, for the payload and the result.
	windowsMechanism = `registry:SecureBoot\State`
)

// platformCapability reads the Secure Boot state key.
//
// Windows creates it only on UEFI systems, so its absence is a real firmware
// answer — this machine booted legacy BIOS/CSM and has no Secure Boot to
// report — rather than a collector failure. Distinguishing the two is the whole
// point: CapNotPresent tells an operator there is nothing to fix, while the
// manifest default this collector replaced claimed Windows itself could not
// answer.
func platformCapability(ctx context.Context) tel.CapabilityState {
	out, _, err := shared.RunCommandOutputContext(ctx, "reg", "query", secureBootKey, "/v", secureBootValue)
	if err != nil {
		return tel.CapNotPresent
	}
	if _, parseErr := parseRegDWORD(out, secureBootValue); parseErr != nil {
		// The key exists but the value did not parse: the mechanism is there
		// and did not answer, which is CapUnsupported, not "no UEFI".
		return tel.CapUnsupported
	}
	return tel.CapSupported
}

func platformSecureBoot(ctx context.Context) signal {
	out, _, err := shared.RunCommandOutputContext(ctx, "reg", "query", secureBootKey, "/v", secureBootValue)
	if err != nil {
		return signal{
			State:    StateUnknown,
			Source:   windowsMechanism,
			Warnings: []string{"Secure Boot state key is not readable"},
		}
	}

	v, parseErr := parseRegDWORD(out, secureBootValue)
	if parseErr != nil {
		return signal{
			State:    StateUnknown,
			Source:   windowsMechanism,
			Warnings: []string{"UEFISecureBootEnabled value did not parse"},
		}
	}

	return signal{State: stateFromDWORD(v), Mechanism: windowsMechanism, Source: windowsMechanism}
}
