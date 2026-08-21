//go:build linux

package protection

import (
	"context"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

// Linux ships no built-in real-time anti-malware scanner and no tamper-
// protection concept, so both controls are genuinely absent rather than
// unreadable.
//
// A third-party product (ClamAV's on-access scanner, an EDR agent) may provide
// something equivalent, but there is no uniform, reliable way to read its state
// across distributions — and guessing from a running process name would put a
// fabricated security assertion on the wire. CapNotPresent says plainly that
// this endpoint has no such control for the agent to report, which is the
// honest answer and the one that keeps these event types correctly blocked here.
const (
	realtimeProtectionCapability = tel.CapNotPresent
	tamperProtectionCapability   = tel.CapNotPresent
)

func platformProtection(ctx context.Context) signal {
	firewall, source, warnings := linuxFirewall(ctx)

	return signal{
		Payload: Payload{
			Firewall: firewall,
			// Left at the zero value: normalize() turns an empty state into
			// "unknown", and the capability manifest already says why.
			RealtimeProtection: Control{State: StateUnknown},
			TamperProtection:   Control{State: StateUnknown},
		},
		Source:   source,
		Warnings: warnings,
	}
}

// linuxFirewall tries the three front-ends in descending order of how directly
// they answer the question. iptables is last because a raw ruleset only implies
// a firewall; ufw and firewalld report an explicit on/off state.
func linuxFirewall(ctx context.Context) (Firewall, string, []string) {
	if out, err := shared.RunCommandContext(ctx, "ufw", "status"); err == nil {
		if p, ok := parseUFWStatus(out); ok {
			return firewallOf([]Profile{p}, "exec:ufw"), "exec:ufw", nil
		}
	}
	if out, err := shared.RunCommandContext(ctx, "firewall-cmd", "--state"); err == nil {
		p := parseFirewalldState(out)
		return firewallOf([]Profile{p}, "exec:firewall-cmd"), "exec:firewall-cmd", nil
	}
	if out, err := shared.RunCommandContext(ctx, "iptables", "-L", "-n"); err == nil {
		p := parseIptablesRules(out)
		return firewallOf([]Profile{p}, "exec:iptables"), "exec:iptables", nil
	}

	return Firewall{State: StateUnknown}, "exec:none",
		[]string{"no supported firewall front-end responded (ufw, firewall-cmd, iptables)"}
}

func firewallOf(profiles []Profile, mechanism string) Firewall {
	return Firewall{
		State:     firewallStateFrom(profiles),
		Profiles:  profiles,
		Mechanism: mechanism,
	}
}
