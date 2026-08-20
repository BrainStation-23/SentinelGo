//go:build darwin

package network

import (
	"context"

	"sentinelgo/internal/osinfo/shared"
)

// platformExtra reads MTU via `ifconfig <if>` (one call per interface — the
// interface count on a Mac is always small, unlike services or processes),
// classifies physical vs virtual from the interface naming convention, and
// reads the single global proxy configuration via `scutil --proxy`.
//
// DHCP state is not collected on macOS in this pass: `ipconfig getpacket
// <if>` (the matrix-documented mechanism) only returns useful output for an
// interface that actually has a live DHCP lease, so a static-vs-inactive
// interface cannot be told apart from this alone without extra corroborating
// calls — left undetermined (nil) rather than guessed.
func platformExtra(ctx context.Context, names []string) signal {
	extra := make(map[string]extraFields, len(names))
	var warnings []string

	for _, name := range names {
		e := extraFields{
			IsVPN:      isVPNInterfaceName(name),
			IsPhysical: classifyDarwinInterface(name),
		}
		if out, err := shared.RunCommandContext(ctx, "ifconfig", name); err == nil {
			e.MTU = parseIfconfigMTU(out)
		} else {
			warnings = append(warnings, "ifconfig failed for "+name)
		}
		extra[name] = e
	}

	sig := signal{Extra: extra, Source: "exec:ifconfig", Warnings: warnings}

	if out, err := shared.RunCommandContext(ctx, "scutil", "--proxy"); err == nil {
		sig.ProxyEnabled, sig.ProxyServer = parseScutilProxy(out)
	} else {
		sig.Warnings = append(sig.Warnings, "scutil --proxy failed")
	}

	return sig
}
