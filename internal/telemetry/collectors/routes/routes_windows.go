//go:build windows

package routes

import (
	"context"

	"github.com/yusufpapurcu/wmi"

	tel "sentinelgo/internal/telemetry"
)

// msftNetRoute mirrors the MSFT_NetRoute fields this collector reads.
//
// Field names must match the CIM property names exactly; the wmi package maps
// by name. Only the modelled properties are selected — MSFT_NetRoute also
// exposes per-route cache and preferred-lifetime values that change on every
// read, and selecting them would be the fingerprint churn this section is
// structured to avoid.
type msftNetRoute struct {
	DestinationPrefix string
	NextHop           string
	InterfaceAlias    string
	RouteMetric       uint16
	Protocol          uint16
	AddressFamily     uint16
}

// platformCapability reports the routing table as readable on Windows.
//
// The real probe is the WMI query itself: opening root\StandardCimv2 costs a
// COM round-trip, and running it twice per cycle (once for Capability, once for
// Collect) would double the collector's cost to learn nothing new. A namespace
// that is genuinely unavailable surfaces as a collection error with its own
// status, which is the honest place for it.
func platformCapability(context.Context) tel.CapabilityState {
	return tel.CapSupported
}

// platformRoutes reads the routing table through the MSFT_NetRoute CIM class.
//
// Native WMI rather than `Get-NetRoute`: CLAUDE.md prefers it for new Windows
// collectors, it avoids a PowerShell launch (~350–900 ms cold) on every cycle,
// and — since nothing here builds a command string — there is no shell for
// host-controlled text such as an interface alias to escape into.
//
// root\StandardCimv2 is the namespace the Get-NetRoute cmdlet itself wraps, so
// this reads the same data the documented tooling does.
func platformRoutes(ctx context.Context) signal {
	const source = "wmi:root/StandardCimv2:MSFT_NetRoute"

	var rows []msftNetRoute
	query := "SELECT DestinationPrefix, NextHop, InterfaceAlias, RouteMetric, Protocol, AddressFamily FROM MSFT_NetRoute"

	// wmi.QueryNamespace is a blocking COM call with no context parameter of
	// its own, so cancellation is honoured on either side of it rather than
	// during it. That keeps a cancelled cycle from publishing a section it no
	// longer has a deadline for, which is what the caller actually needs.
	if err := ctx.Err(); err != nil {
		return signal{Err: err, Source: source}
	}
	if err := wmi.QueryNamespace(query, &rows, `root\StandardCimv2`); err != nil {
		return signal{
			Err:      err,
			Source:   source,
			Warnings: []string{"MSFT_NetRoute query failed"},
		}
	}
	if err := ctx.Err(); err != nil {
		return signal{Err: err, Source: source}
	}

	out := make([]Route, 0, len(rows))
	for _, r := range rows {
		family := windowsAddressFamily(r.AddressFamily)
		metric := int(r.RouteMetric)
		out = append(out, Route{
			Destination: normalizeDestination(r.DestinationPrefix, family),
			Gateway:     normalizeWindowsNextHop(r.NextHop),
			Interface:   r.InterfaceAlias,
			Metric:      &metric,
			Source:      windowsRouteProtocol(r.Protocol),
			Family:      family,
		})
	}

	return signal{Routes: out, Source: source}
}
