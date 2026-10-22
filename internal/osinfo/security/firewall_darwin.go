package security

import "sentinelgo/internal/osinfo/shared"

const socketfilterfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"

// darwinFirewallCheck rates risky services against the Application Firewall.
// It filters per application, not per port, so only its two global states
// give a verdict: off ("disabled") and block-all ("blocked"). Otherwise
// whether a service is reachable depends on its app's entry, which isn't
// read, so the verdict is "unknown".
func darwinFirewallCheck(profiles []shared.FirewallProfile) firewallCheck {
	if len(profiles) == 0 {
		return constantCheck(firewallUnknown)
	}
	if !anyFirewallEnabled(profiles) {
		return constantCheck(firewallDisabled)
	}
	blockAll, _ := darwinRunCommand(socketfilterfw, "--getblockall")
	global, _ := darwinRunCommand(socketfilterfw, "--getglobalstate")
	if alfBlocksAll(blockAll, global) {
		return constantCheck(firewallBlocked)
	}
	return constantCheck(firewallUnknown)
}
