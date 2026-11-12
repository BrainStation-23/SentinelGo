package policy

// Network controls (#427, contract proposed on Compliance-OS#910): on
// Windows the agent can't refuse a file copy by content, but it can stop an
// app from reaching the network (WFP). Two controls, both under
// modules.files.network_control and both off unless the bundle turns them
// on:
//
//   - blocked_apps: apps admins mark as unsanctioned get no network access,
//     except to allow_destinations;
//   - taint_block: an egress app that reads a file a file.upload policy
//     would block loses new connections for a few minutes.
//
// audit_only wins, as for every file control: nothing is blocked, the agent
// only records what it would have done.

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// NetworkControl is modules.files.network_control.
type NetworkControl struct {
	Enabled bool `json:"enabled"`
	// BlockedApps are the unsanctioned apps, by GOOS (only "windows" is
	// applied), in the App shape egress_apps uses.
	BlockedApps map[string][]App `json:"blocked_apps"`
	TaintBlock  TaintBlock       `json:"taint_block"`
	// AllowDestinations are host names, "*.example.com" patterns, IP
	// addresses or CIDR ranges that blocked and tainted apps can always
	// reach.
	AllowDestinations []string `json:"allow_destinations"`

	// DecodeError is why the block couldn't be read; the controls are then
	// off.
	DecodeError string `json:"-"`
}

// TaintBlock cuts an egress app's new connections for Minutes after it read
// a file that a file.upload policy would block.
type TaintBlock struct {
	Enabled bool `json:"enabled"`
	Minutes int  `json:"minutes"`
}

// Network control limits.
const (
	DefaultTaintBlockMinutes = 10
	MinTaintBlockMinutes     = 1
	MaxTaintBlockMinutes     = 60
	maxBlockedApps           = 500
	maxAllowDestinations     = 2000
)

// UnmarshalJSON never fails: an unreadable block turns the controls off with
// DecodeError set, so it can't turn file DLP off.
func (n *NetworkControl) UnmarshalJSON(data []byte) error {
	type plain NetworkControl
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		*n = NetworkControl{DecodeError: fmt.Sprintf("modules.files.network_control: %v", err)}
		return nil
	}
	*n = NetworkControl(p)
	return nil
}

func (n *NetworkControl) normalize() {
	if n.DecodeError != "" {
		n.Enabled = false
	}
	if n.TaintBlock.Minutes <= 0 {
		n.TaintBlock.Minutes = DefaultTaintBlockMinutes
	}
	n.TaintBlock.Minutes = min(max(n.TaintBlock.Minutes, MinTaintBlockMinutes), MaxTaintBlockMinutes)
	for goos, apps := range n.BlockedApps {
		if len(apps) > maxBlockedApps {
			n.BlockedApps[goos] = apps[:maxBlockedApps]
		}
	}
	n.AllowDestinations = cleanDestinations(n.AllowDestinations)
}

// cleanDestinations keeps valid host patterns (lower case) and IP addresses
// or CIDR ranges (in canonical form), without duplicates.
func cleanDestinations(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, d := range in {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if p, ok := parseRange(d); ok {
			d = p.String()
		} else if !validHostPattern(d) {
			continue
		}
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
		if len(out) == maxAllowDestinations {
			break
		}
	}
	return out
}

// parseRange reads an IP address (a /32 or /128) or a CIDR range.
func parseRange(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// Allowed splits AllowDestinations into host patterns and address ranges.
func (n NetworkControl) Allowed() (hosts []string, ranges []netip.Prefix) {
	for _, d := range n.AllowDestinations {
		if p, ok := parseRange(d); ok {
			ranges = append(ranges, p)
		} else {
			hosts = append(hosts, d)
		}
	}
	return hosts, ranges
}

// ControlsNetwork reports whether m turns a network control on for goos:
// the module and the block are on, and there is an app to block or taint
// blocks are on.
func (m FilesModule) ControlsNetwork(goos string) bool {
	n := m.NetworkControl
	return m.Enabled && m.DecodeError == "" && n.Enabled && (len(n.BlockedApps[goos]) > 0 || n.TaintBlock.Enabled)
}
