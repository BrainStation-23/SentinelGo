package network

import (
	"encoding/json"
	"strconv"
	"strings"
)

// This file holds every platform's parsing/classification as pure functions
// with no build tag, so it is unit tested on every host regardless of GOOS.

// vpnPrefixes are interface-name prefixes docs/telemetry/03-collection-matrix.md
// documents as VPN indicators across platforms: Windows/Linux tun/tap/wg
// (WireGuard) devices, macOS utun, and ppp links used by several VPN clients
// on every platform.
var vpnPrefixes = []string{"tun", "tap", "wg", "utun", "ppp", "ipsec"}

// isVPNInterfaceName reports whether name matches a known VPN interface
// naming convention. This is a heuristic, not a certainty — a renamed
// interface would be missed — but it is the mechanism the matrix doc itself
// recommends, and false negatives here are safer than a fabricated positive.
func isVPNInterfaceName(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range vpnPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// ── Windows: Get-NetIPInterface + Get-NetAdapter ────────────────────────────

type windowsIfaceRow struct {
	Name    string `json:"Name"`
	MTU     int    `json:"Mtu"`
	Dhcp    string `json:"Dhcp"`
	Virtual bool   `json:"Virtual"`
}

// parseWindowsInterfaces parses the combined PowerShell script's JSON. A
// single interface serializes as a bare object rather than a one-element
// array, the same ambiguity handled throughout this codebase's other
// PowerShell-JSON call sites.
func parseWindowsInterfaces(output string) ([]windowsIfaceRow, error) {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil, nil
	}

	var rows []windowsIfaceRow
	if err := json.Unmarshal([]byte(output), &rows); err == nil {
		return rows, nil
	}

	var single windowsIfaceRow
	if err := json.Unmarshal([]byte(output), &single); err != nil {
		return nil, err
	}
	return []windowsIfaceRow{single}, nil
}

func (r windowsIfaceRow) toExtra() extraFields {
	physical := !r.Virtual
	e := extraFields{
		MTU:        r.MTU,
		IsPhysical: &physical,
		IsVPN:      isVPNInterfaceName(r.Name),
	}
	switch strings.ToLower(r.Dhcp) {
	case "enabled":
		dhcp := true
		e.DHCPEnabled = &dhcp
	case "disabled":
		dhcp := false
		e.DHCPEnabled = &dhcp
	}
	return e
}

// ── Linux ────────────────────────────────────────────────────────────────────

// parseNmcliDHCP interprets `nmcli -g IP4.DHCP4 device show <if>` output.
// NetworkManager prints "yes" for a DHCP-assigned address and "no" (or
// nothing) otherwise.
func parseNmcliDHCP(output string) *bool {
	v := strings.ToLower(strings.TrimSpace(output))
	switch v {
	case "yes":
		dhcp := true
		return &dhcp
	case "no":
		dhcp := false
		return &dhcp
	default:
		return nil
	}
}

// ── macOS: ifconfig + scutil ────────────────────────────────────────────────

// parseIfconfigMTU extracts the MTU value from `ifconfig <if>` output, whose
// first line looks like "en0: flags=8863<UP,BROADCAST,...> mtu 1500".
func parseIfconfigMTU(output string) int {
	idx := strings.Index(output, "mtu ")
	if idx < 0 {
		return 0
	}
	rest := strings.TrimSpace(output[idx+len("mtu "):])
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	n, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0
	}
	return n
}

// darwinVirtualPrefixes are macOS interface names that are never physical
// hardware: loopback, VPN tunnels, AirDrop/AWDL, Wi-Fi Direct/AP mode,
// bridges, and the legacy 6to4/gif tunnel interfaces.
var darwinVirtualPrefixes = []string{"lo", "utun", "bridge", "awdl", "llw", "gif", "stf", "p2p", "ap", "anpi"}

// classifyDarwinInterface reports whether name is physical hardware, or nil
// when the naming convention does not confidently say either way. "en*"
// covers Apple's real Ethernet/Wi-Fi/Thunderbolt hardware consistently
// enough to report true; anything matching a known-virtual prefix reports
// false; anything else is left undetermined rather than guessed.
func classifyDarwinInterface(name string) *bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "en") {
		physical := true
		return &physical
	}
	for _, p := range darwinVirtualPrefixes {
		if strings.HasPrefix(lower, p) {
			physical := false
			return &physical
		}
	}
	return nil
}

// parseScutilProxy parses `scutil --proxy` output — indented "Key : Value"
// lines — for the global HTTP proxy state.
func parseScutilProxy(output string) (enabled *bool, server string) {
	fields := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if key != "" {
			fields[key] = val
		}
	}

	if v, ok := fields["HTTPEnable"]; ok {
		on := v == "1"
		enabled = &on
	}
	host := fields["HTTPProxy"]
	port := fields["HTTPPort"]
	if host != "" {
		server = host
		if port != "" {
			server += ":" + port
		}
	}
	return enabled, server
}
