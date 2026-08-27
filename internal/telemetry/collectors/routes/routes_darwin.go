//go:build darwin

package routes

import (
	"context"
	"os/exec"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

// platformCapability reports whether netstat is available.
//
// netstat ships with every macOS release, so this effectively always answers
// supported; the probe exists so a stripped or PATH-broken host reports the
// honest CapUnsupported instead of an empty section.
func platformCapability(context.Context) tel.CapabilityState {
	if _, err := exec.LookPath("netstat"); err != nil {
		return tel.CapUnsupported
	}
	return tel.CapSupported
}

// platformRoutes reads the routing table through `netstat -rn`.
//
// One invocation returns both the Internet and Internet6 tables, so unlike
// Linux there is no per-family split to reconcile. `-n` keeps it numeric: name
// resolution would otherwise make this collector issue DNS queries for every
// gateway, turning an inventory read into network traffic and making its
// runtime depend on resolver latency.
//
// Arguments are a fixed argv with no shell involved — see the Linux file.
func platformRoutes(ctx context.Context) signal {
	out, err := shared.RunCommandContext(ctx, "netstat", "-rn")
	if err != nil {
		return signal{
			Err:      err,
			Source:   "exec:netstat -rn",
			Warnings: []string{"netstat -rn failed"},
		}
	}
	return signal{
		Routes: parseNetstatRoutes(out),
		Source: "exec:netstat -rn",
	}
}
