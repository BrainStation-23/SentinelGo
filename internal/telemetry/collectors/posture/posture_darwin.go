//go:build darwin

package posture

import (
	"context"

	"sentinelgo/internal/osinfo/shared"
)

// platformPosture reports privileged account membership only on macOS.
// `pwpolicy getaccountpolicies` is the matrix-adjacent mechanism for
// password policy, but its output is a nonstandard text/XML hybrid that
// cannot be parsed reliably without a live macOS host to verify against —
// left for a follow-up rather than shipped as a guess.
func platformPosture(ctx context.Context) signal {
	out, err := shared.RunCommandContext(ctx, "dscl", ".", "-read", "/Groups/admin", "GroupMembership")
	if err != nil {
		return signal{Warnings: []string{"dscl admin group read failed"}, Err: err}
	}

	return signal{
		PrivilegedAccounts: parseDsclGroupMembership(out),
		Source:             "exec:dscl",
	}
}
