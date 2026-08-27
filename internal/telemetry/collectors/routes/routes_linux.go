//go:build linux

package routes

import (
	"context"
	"os/exec"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

// platformCapability reports whether iproute2 is installed.
//
// A LookPath is the entire probe: it costs no subprocess, and the only reason
// the routing table would be unreadable on Linux is `ip` being absent from a
// minimal image. That is CapUnsupported — the host, not the OS, cannot answer —
// so it is never reported as unavailable_on_os.
func platformCapability(context.Context) tel.CapabilityState {
	if _, err := exec.LookPath("ip"); err != nil {
		return tel.CapUnsupported
	}
	return tel.CapSupported
}

// platformRoutes reads both address families through iproute2.
//
// Arguments are passed as a fixed argv, never a shell string: shared.RunCommand*
// executes the binary directly with no shell, so nothing here can be influenced
// by hostnames, interface names or any other host-controlled text.
//
// The two families are collected independently and a failure in one is a
// warning rather than a total failure. A host with IPv6 disabled at the kernel
// level makes `ip -6 route show` fail, and losing the whole IPv4 table because
// of that would be the wrong trade.
func platformRoutes(ctx context.Context) signal {
	var sig signal
	sig.Source = "exec:ip route"

	v4, err := shared.RunCommandContext(ctx, "ip", "-4", "route", "show")
	if err != nil {
		sig.Warnings = append(sig.Warnings, "ip -4 route show failed")
		sig.Err = err
	} else {
		sig.Routes = append(sig.Routes, parseIPRoute(v4, FamilyIPv4)...)
	}

	v6, err6 := shared.RunCommandContext(ctx, "ip", "-6", "route", "show")
	if err6 != nil {
		sig.Warnings = append(sig.Warnings, "ip -6 route show failed")
		// Only promote this to the section error if IPv4 also failed; otherwise
		// the payload is usable and the warning carries the detail.
		if sig.Err == nil && len(sig.Routes) == 0 {
			sig.Err = err6
		}
	} else {
		sig.Routes = append(sig.Routes, parseIPRoute(v6, FamilyIPv6)...)
	}

	return sig
}
