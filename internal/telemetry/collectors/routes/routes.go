// Package routes implements the telemetry Routing Table collector, filling the
// "routes" section.
//
// It closes what docs/telemetry/02-gap-analysis.md records as gap 13
// ("Routing / network config — routing table missing") and finally gives
// CapKeyNetworkRoutingTable an owner. That key existed in the capability
// manifest from the start with no collector behind it, so every endpoint
// reported the manifest default for it; config carried a matching
// `collect_routing_table` flag that was plumbed all the way through to
// CollectorConfig and then read by nothing at all.
//
// # Why its own section rather than fields on "network"
//
// The routing table is the volatile part of network state: it changes when a
// VPN connects, when DHCP renews, when a container engine starts. The "network"
// section is ClassInventory and fingerprinted, so folding routes into it would
// make an unrelated VPN toggle re-upload every adapter, MTU and DNS server on
// the device. A separate section keeps that churn in its own fingerprint, on
// its own reconcile clock, and lets the routing table be chunked independently.
//
// # Opt-in
//
// Collection is off unless CollectorConfig.CollectRoutingTable is set. When
// off, Capability reports CapDisabled — which makes RunAll skip Collect
// entirely, so the default configuration pays nothing and the backend is told
// the honest reason the section is absent ("an administrator turned this off")
// rather than inheriting a claim about the platform.
//
// Payload is a bare slice because SectionRoutes is registered Chunked in
// section.go, and telemetry.ChunkSection requires the value Collect returns to
// reflect as a slice directly — the same constraint the patches and processes
// collectors document.
//
// ARP/neighbour-cache collection is deliberately NOT part of this collector.
// It is a separate dataset with a separate privacy profile (it enumerates other
// hosts on the local network, not this endpoint), and belongs behind its own
// flag if it is ever wanted.
package routes

import (
	"context"
	"sort"

	tel "sentinelgo/internal/telemetry"
)

// Name is the collector's identifier, also used as its section name.
const Name = tel.SectionRoutes

// maxRoutes is a hard ceiling applied even when CollectorConfig.MaxItems is
// unset (zero means "unlimited" everywhere else in the layer).
//
// A routing table is normally 10–60 entries. It is not normally 20,000 — but a
// host running a BGP daemon, a busy container engine, or a full-tunnel VPN with
// per-subnet split routes can produce exactly that, and "unlimited" is the
// default. This bound is what stops one such host from serialising a
// multi-megabyte section into a queue whose per-message cap would then
// dead-letter it. Truncation is reported as a warning, never silently.
const maxRoutes = 2000

// Address families, so callers need not pattern-match on the destination.
const (
	FamilyIPv4 = "ipv4"
	FamilyIPv6 = "ipv6"
)

// Route is one normalised routing-table entry.
//
// The model is deliberately the intersection of what all three platforms can
// state reliably. Fields a platform cannot answer are left empty rather than
// guessed, and nothing here is a per-cycle-changing value: route cache hits,
// expiry timers, reference counts and byte counters are all excluded on
// purpose, because SectionRoutes is fingerprinted and those fields would make
// an otherwise-unchanged routing table look different on every single cycle.
type Route struct {
	// Destination is the destination network in CIDR form ("0.0.0.0/0",
	// "10.0.0.0/8", "::/0"). A default route is always the zero-length prefix
	// for its family, never the platform's own word for it ("default").
	Destination string `json:"destination"`
	// Gateway is the next hop, or empty for an on-link route that has none.
	// Empty means "directly connected", which is information — not a failed
	// read.
	Gateway string `json:"gateway,omitempty"`
	// Interface is the outgoing interface as the OS names it, matching the
	// "name" field of the network section's interfaces.
	Interface string `json:"interface,omitempty"`
	// Metric is the route metric/priority. Nil when the platform did not state
	// one: 0 is a real, meaningful metric on Linux and Windows, so a missing
	// value must not collapse into it.
	Metric *int `json:"metric,omitempty"`
	// Source is how the route came to exist, normalised to a small vocabulary:
	// "static", "dhcp", "kernel", "ra" (IPv6 router advertisement), "local",
	// or a routing-daemon name where one is reported. Empty when the platform
	// does not say — macOS in particular does not.
	Source string `json:"source,omitempty"`
	// Family is FamilyIPv4 or FamilyIPv6.
	Family string `json:"family"`
}

// Payload is the wire shape of the "routes" section — a bare slice, see the
// package doc.
type Payload []Route

// Collector implements telemetry.Collector for the routing table.
type Collector struct{}

// New returns the Routing Table collector.
func New() *Collector { return &Collector{} }

func (c *Collector) Name() string       { return Name }
func (c *Collector) Section() string    { return tel.SectionRoutes }
func (c *Collector) SchemaVersion() int { return 1 }

// Capability reports why the routing table is or is not collected.
//
// The order matters: configuration is checked before the platform probe, so a
// host with the feature switched off reports CapDisabled and never runs the
// probe. Reporting a platform verdict for a host that simply was not asked
// would be a claim about the platform that nothing verified.
func (c *Collector) Capability(ctx context.Context, cfg tel.CollectorConfig) (string, tel.CapabilityState) {
	if !cfg.CollectRoutingTable {
		return tel.CapKeyNetworkRoutingTable, tel.CapDisabled
	}
	return tel.CapKeyNetworkRoutingTable, platformCapability(ctx)
}

// Collect gathers the routing table.
//
// The config check is repeated here rather than trusted from Capability.
// RunAll does skip Collect when Capability is not supported, but Collect is
// also reachable directly (the -telemetry-cycle debug command, tests), and a
// privacy/cost gate that only holds on one call path is not a gate.
func (c *Collector) Collect(ctx context.Context, cfg tel.CollectorConfig) (any, tel.CollectorResult) {
	res, done := tel.NewResult(c.Name(), c.Section())

	if !cfg.CollectRoutingTable {
		r := *done(nil, "disabled_by_config", 0)
		r.Status = tel.StatusUnsupported
		return Payload(nil), r
	}

	sig := platformRoutes(ctx)
	for _, w := range sig.Warnings {
		res.AddWarning(w)
	}

	items := Normalize(sig.Routes)

	limit := maxRoutes
	if cfg.MaxItems > 0 && cfg.MaxItems < limit {
		limit = cfg.MaxItems
	}
	if len(items) > limit {
		res.AddWarning("routing table truncated to the configured item limit")
		items = items[:limit]
	}

	return Payload(items), *done(sig.Err, sig.Source, len(items))
}

// Normalize drops entries with no destination and sorts the rest
// deterministically.
//
// Sorting is not cosmetic. SectionRoutes is fingerprinted, and Fingerprint
// hashes the serialised payload, so an unchanged routing table reported in a
// different order every cycle would hash differently every cycle and re-upload
// forever. `ip route` and `netstat -rn` both emit in kernel-internal order,
// which is not stable across reads.
func Normalize(in []Route) []Route {
	out := make([]Route, 0, len(in))
	for _, r := range in {
		if r.Destination == "" {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		if a.Destination != b.Destination {
			return a.Destination < b.Destination
		}
		if a.Interface != b.Interface {
			return a.Interface < b.Interface
		}
		if a.Gateway != b.Gateway {
			return a.Gateway < b.Gateway
		}
		return metricOf(a) < metricOf(b)
	})
	return out
}

// metricOf gives a missing metric a sort position without inventing a value in
// the payload itself.
func metricOf(r Route) int {
	if r.Metric == nil {
		return -1
	}
	return *r.Metric
}

// signal is what platform code supplies before assembling Payload.
type signal struct {
	Routes   []Route
	Err      error
	Source   string
	Warnings []string
}
