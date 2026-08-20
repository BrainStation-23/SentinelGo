//go:build windows

package directory

import (
	"context"
	"fmt"
	"strings"

	"github.com/yusufpapurcu/wmi"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

type win32ComputerSystem struct {
	PartOfDomain bool
	Domain       string
}

// platformCapability reports CapSupported unconditionally: WMI and dsregcmd
// are both native OS components present on every supported Windows target.
func platformCapability(context.Context) tel.CapabilityState {
	return tel.CapSupported
}

// platformSignal gets on-prem AD state from WMI (reliable, no text parsing)
// and Entra ID state from `dsregcmd /status` (the only source for it).
//
// dsregcmd's own DomainJoined line is not used: it is redundant with the WMI
// field and its table layout has drifted across Windows versions, so relying
// on WMI for that half keeps this resilient to a dsregcmd format change.
func platformSignal(ctx context.Context) (sig signal) {
	defer func() {
		if r := recover(); r != nil {
			sig.Warnings = append(sig.Warnings, "wmi query panicked")
			sig.ADErr = fmt.Errorf("win32_computersystem panic: %w", tel.ErrWMIQuery)
		}
	}()

	var sources []string

	var cs []win32ComputerSystem
	switch err := wmi.Query("SELECT PartOfDomain, Domain FROM Win32_ComputerSystem", &cs); {
	case err != nil:
		sig.Warnings = append(sig.Warnings, "Win32_ComputerSystem query failed")
		sig.ADErr = fmt.Errorf("win32_computersystem: %w", tel.ErrWMIQuery)
	case len(cs) == 0:
		sig.Warnings = append(sig.Warnings, "Win32_ComputerSystem returned no rows")
		sig.ADErr = fmt.Errorf("win32_computersystem: %w", tel.ErrEmptyOutput)
	default:
		joined := cs[0].PartOfDomain
		sig.DomainJoined = &joined
		if joined {
			sig.Domain = strings.TrimSpace(cs[0].Domain)
		}
		sources = append(sources, "wmi:Win32_ComputerSystem")
	}

	// dsregcmd's exit code is not documented to reliably mean "not joined";
	// use RunCommandOutputContext so a non-zero exit still returns the status
	// text instead of being discarded, the same caution the codebase applies
	// to smartctl and yum.
	out, _, err := shared.RunCommandOutputContext(ctx, "dsregcmd", "/status")
	if err != nil {
		sig.Warnings = append(sig.Warnings, "dsregcmd /status failed to run")
		sig.EntraErr = err
	} else {
		entraJoined, tenantID, deviceID := parseDsregcmd(out)
		sig.EntraJoined = &entraJoined
		sig.TenantID = tenantID
		sig.DeviceID = deviceID
		sources = append(sources, "exec:dsregcmd")
	}

	sig.Source = strings.Join(sources, ", ")
	return sig
}
