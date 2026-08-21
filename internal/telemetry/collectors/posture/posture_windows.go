//go:build windows

package posture

import (
	"context"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

func platformPosture(ctx context.Context) signal {
	var warnings []string
	var sources []string

	var policy PasswordPolicy
	if out, err := shared.RunCommandContext(ctx, "net", "accounts"); err == nil {
		policy = parseNetAccounts(out)
		sources = append(sources, "exec:net accounts")
	} else {
		warnings = append(warnings, "net accounts failed to run")
	}

	var members []string
	if out, err := shared.RunCommandContext(ctx, "net", "localgroup", "Administrators"); err == nil {
		members = parseNetLocalgroupMembers(out)
		sources = append(sources, "exec:net localgroup")
	} else {
		warnings = append(warnings, "net localgroup Administrators failed to run")
	}

	return signal{
		Policy:             policy,
		PrivilegedAccounts: members,
		Source:             strings.Join(sources, ", "),
		Warnings:           warnings,
	}
}
