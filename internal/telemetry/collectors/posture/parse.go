package posture

import "strings"

// This file holds every platform's parsing as pure functions with no build
// tag, so it is unit tested on every host regardless of GOOS.

// ── Windows: net accounts / net localgroup ──────────────────────────────────

// parseNetAccounts parses `net accounts`'s "Key:   Value" lines (the same
// right-aligned colon style already handled for diskutil/dsregcmd) into a
// PasswordPolicy.
func parseNetAccounts(output string) PasswordPolicy {
	fields := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		val := strings.TrimSpace(line[idx+1:])
		if key != "" {
			fields[key] = val
		}
	}

	var p PasswordPolicy
	if v, ok := parseNetAccountsInt(fields["minimum password length"]); ok {
		p.MinLength = &v
	}
	if v, ok := parseNetAccountsInt(fields["minimum password age (days)"]); ok {
		p.MinAgeDays = &v
	}
	if v, ok := parseNetAccountsInt(fields["maximum password age (days)"]); ok {
		p.MaxAgeDays = &v
	}
	if v, ok := parseNetAccountsInt(fields["lockout threshold"]); ok {
		p.LockoutThreshold = &v
	}
	if v, ok := parseNetAccountsInt(fields["lockout duration (minutes)"]); ok {
		p.LockoutDurationMinutes = &v
	}
	return p
}

// parseNetAccountsInt parses one of net accounts's numeric fields, which can
// also read "Never" or "Unlimited" — a real policy value, not an integer,
// reported as "not determined" (false) rather than guessed.
func parseNetAccountsInt(v string) (int, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	n := 0
	for _, r := range v {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}

// parseNetLocalgroupMembers parses `net localgroup Administrators` output: a
// header block, a dashed separator line, one member per line, then a
// trailing "The command completed successfully." line.
func parseNetLocalgroupMembers(output string) []string {
	lines := strings.Split(output, "\n")
	start := -1
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "---") {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return nil
	}

	var members []string
	for _, line := range lines[start:] {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "The command completed") {
			continue
		}
		members = append(members, line)
	}
	return members
}

// ── Linux: login.defs / faillock.conf / /etc/group ──────────────────────────

// parseLoginDefs parses /etc/login.defs's "KEY value" lines (whitespace
// separated, "#" comments), extracting PASS_MIN_LEN, PASS_MIN_DAYS and
// PASS_MAX_DAYS.
func parseLoginDefs(content string) PasswordPolicy {
	var p PasswordPolicy
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, ok := parseNetAccountsInt(fields[1])
		if !ok {
			continue
		}
		switch fields[0] {
		case "PASS_MIN_LEN":
			p.MinLength = &v
		case "PASS_MIN_DAYS":
			p.MinAgeDays = &v
		case "PASS_MAX_DAYS":
			p.MaxAgeDays = &v
		}
	}
	return p
}

// parseFaillockConf reads /etc/security/faillock.conf's "deny = N" line for
// the lockout threshold. Absence is common and legitimate (no PAM lockout
// module configured, or a distribution using pam_tally2 instead) rather than
// an error.
func parseFaillockConf(content string) *int {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "deny") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		if v, ok := parseNetAccountsInt(line[idx+1:]); ok {
			return &v
		}
	}
	return nil
}

// parseEtcGroupMembers finds groupName's member list in /etc/group content
// (format "name:x:gid:member1,member2").
func parseEtcGroupMembers(content, groupName string) []string {
	prefix := groupName + ":"
	for _, line := range strings.Split(content, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 || fields[3] == "" {
			return nil
		}
		var members []string
		for _, m := range strings.Split(fields[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				members = append(members, m)
			}
		}
		return members
	}
	return nil
}

// ── macOS: dscl ──────────────────────────────────────────────────────────────

// parseDsclGroupMembership parses `dscl . -read /Groups/admin
// GroupMembership` output: "GroupMembership: user1 user2 root".
func parseDsclGroupMembership(output string) []string {
	const prefix = "GroupMembership:"
	for _, line := range strings.Split(output, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, prefix))
		if rest == "" {
			return nil
		}
		return strings.Fields(rest)
	}
	return nil
}
