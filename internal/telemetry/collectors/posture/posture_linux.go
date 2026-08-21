//go:build linux

package posture

import (
	"context"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

func platformPosture(_ context.Context) signal {
	var warnings []string
	var sources []string

	var policy PasswordPolicy
	if content, err := shared.ReadFileContent("/etc/login.defs"); err == nil {
		policy = parseLoginDefs(content)
		sources = append(sources, "file:/etc/login.defs")
	} else {
		warnings = append(warnings, "/etc/login.defs unreadable")
	}

	// faillock.conf is genuinely absent on plenty of hosts (pam_tally2 or no
	// lockout module at all); that is not itself a warning-worthy condition.
	if content, err := shared.ReadFileContent("/etc/security/faillock.conf"); err == nil {
		if threshold := parseFaillockConf(content); threshold != nil {
			policy.LockoutThreshold = threshold
			sources = append(sources, "file:/etc/security/faillock.conf")
		}
	}

	var members []string
	if content, err := shared.ReadFileContent("/etc/group"); err == nil {
		// sudo (Debian/Ubuntu convention) and wheel (RHEL/Fedora/SUSE
		// convention) are both checked; a host uses at most one in practice.
		members = append(members, parseEtcGroupMembers(content, "sudo")...)
		members = append(members, parseEtcGroupMembers(content, "wheel")...)
		sources = append(sources, "file:/etc/group")
	} else {
		warnings = append(warnings, "/etc/group unreadable")
	}

	return signal{
		Policy:             policy,
		PrivilegedAccounts: members,
		Source:             strings.Join(sources, ", "),
		Warnings:           warnings,
	}
}
