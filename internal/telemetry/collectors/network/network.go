// Package network implements the telemetry lightweight Network collector,
// filling the "network" section: interfaces, addresses, gateway and DNS
// (reused read-only from internal/osinfo/network, which already collects
// them correctly) plus the fields docs/telemetry/02-gap-analysis.md marks
// missing — MTU, DHCP state, physical-vs-virtual classification, proxy
// configuration, and VPN detection.
//
// This is deliberately the lightweight pass: routing tables and the ARP/
// neighbour cache are detailed telemetry behind their own opt-in flag per
// the collection matrix, not part of every cycle, and are not collected
// here.
//
// One disclosed limitation shared by every platform's proxy detection: this
// agent runs as a system service (SYSTEM on Windows, root on Linux/macOS),
// so the proxy configuration it can read is the service account's own — not
// necessarily what an interactively logged-in user's browser actually uses.
// Reporting that scoped, real answer is preferable to fabricating a
// per-user value this process cannot see.
package network

import (
	"context"
	"sort"

	stdnet "sentinelgo/internal/osinfo/network"
	tel "sentinelgo/internal/telemetry"
)

// Name is the collector's identifier, also used as its section name.
const Name = tel.SectionNetwork

// Interface describes one network adapter.
type Interface struct {
	Name           string   `json:"name"`
	MACAddress     string   `json:"mac_address,omitempty"`
	AdapterType    string   `json:"adapter_type,omitempty"`
	IsUp           bool     `json:"is_up"`
	MTU            int      `json:"mtu,omitempty"`
	IPv4Addresses  []string `json:"ipv4_addresses,omitempty"`
	IPv6Addresses  []string `json:"ipv6_addresses,omitempty"`
	DefaultGateway string   `json:"default_gateway,omitempty"`
	DNSServers     []string `json:"dns_servers,omitempty"`
	// IsPhysical and DHCPEnabled are *bool: nil means this platform's
	// mechanism could not determine the answer for this specific interface,
	// which must not collapse to a guessed false. See the directory
	// collector's DomainJoined field for the precedent this follows.
	IsPhysical  *bool `json:"is_physical,omitempty"`
	DHCPEnabled *bool `json:"dhcp_enabled,omitempty"`
	IsVPN       bool  `json:"is_vpn"`
}

// Payload is the wire shape of the "network" section.
type Payload struct {
	Interfaces []Interface `json:"interfaces"`
	// ProxyEnabled/ProxyServer are device-level (the service account's own
	// configuration — see the package doc's disclosed limitation), not
	// per-interface.
	ProxyEnabled *bool  `json:"proxy_enabled,omitempty"`
	ProxyServer  string `json:"proxy_server,omitempty"`
}

// signal is what platform code supplies before assembling Payload.
type signal struct {
	// Extra is keyed by interface name, filling in what internal/osinfo/network
	// does not already provide.
	Extra        map[string]extraFields
	ProxyEnabled *bool
	ProxyServer  string
	Err          error
	Source       string
	Warnings     []string
}

// extraFields is the per-interface data this collector adds.
type extraFields struct {
	MTU         int
	IsPhysical  *bool
	DHCPEnabled *bool
	IsVPN       bool
}

// Collector implements telemetry.Collector for lightweight network inventory.
type Collector struct{}

// New returns the Network collector.
func New() *Collector { return &Collector{} }

func (c *Collector) Name() string       { return Name }
func (c *Collector) Section() string    { return tel.SectionNetwork }
func (c *Collector) SchemaVersion() int { return 1 }

// Capability reports network enumeration as always supported: every
// supported platform can list its own interfaces.
func (c *Collector) Capability(context.Context, tel.CollectorConfig) (string, tel.CapabilityState) {
	return "", tel.CapSupported
}

// Collect gathers lightweight network inventory.
func (c *Collector) Collect(ctx context.Context, _ tel.CollectorConfig) (any, tel.CollectorResult) {
	res, done := tel.NewResult(c.Name(), c.Section())

	adapters := stdnet.Get()
	names := make([]string, 0, len(adapters))
	for _, a := range adapters {
		names = append(names, a.InterfaceName)
	}
	sig := platformExtra(ctx, names)
	for _, w := range sig.Warnings {
		res.AddWarning(w)
	}

	interfaces := make([]Interface, 0, len(adapters))
	for _, a := range adapters {
		extra := sig.Extra[a.InterfaceName]
		iface := Interface{
			Name:           a.InterfaceName,
			MACAddress:     a.MACAddress,
			AdapterType:    a.AdapterType,
			IsUp:           a.IsConnected,
			MTU:            extra.MTU,
			DefaultGateway: a.DefaultGateway,
			DNSServers:     a.DNSServers,
			IsPhysical:     extra.IsPhysical,
			DHCPEnabled:    extra.DHCPEnabled,
			IsVPN:          extra.IsVPN,
		}
		for _, ip := range a.IPv4Addresses {
			if ip.Address != "" {
				iface.IPv4Addresses = append(iface.IPv4Addresses, ip.Address)
			}
		}
		for _, ip := range a.IPv6Addresses {
			if ip.Address != "" {
				iface.IPv6Addresses = append(iface.IPv6Addresses, ip.Address)
			}
		}
		interfaces = append(interfaces, iface)
	}
	sortInterfaces(interfaces)

	payload := Payload{
		Interfaces:   interfaces,
		ProxyEnabled: sig.ProxyEnabled,
		ProxyServer:  sig.ProxyServer,
	}

	return payload, *done(sig.Err, sig.Source, len(interfaces))
}

// sortInterfaces orders the list deterministically by name, so an unchanged
// interface set hashes identically cycle to cycle — Fingerprint's documented
// requirement for any list payload.
func sortInterfaces(ifaces []Interface) {
	sort.Slice(ifaces, func(i, j int) bool { return ifaces[i].Name < ifaces[j].Name })
}
