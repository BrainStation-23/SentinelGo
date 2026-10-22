package users

// Fuzz target for the identity parsers (#223). They read tool output the
// agent doesn't control (the Windows identity probe, dsregcmd, who, last,
// dscl, dsconfigad, realm, getent and the passwd/group files), so parsing
// must never panic on unexpected input.
//
// The seed corpus runs as an ordinary unit test under `go test ./...`.
// To fuzz: go test -run='^$' -fuzz='^FuzzIdentityParsers$' -fuzztime=1m ./internal/osinfo/users/

import (
	"strings"
	"testing"
	"time"
)

func FuzzIdentityParsers(f *testing.F) {
	for _, s := range []string{
		"", "\n", ":", " : ", "=", "(", ")", "{", "[]", "null", `{"admins":null,"admin_paths":[{}]}`,
		`{"admins":[{"name":"","sid":"S-1-12-1-","source":"AzureAD","class":"Group"}],"machine_sid":""}`,
		`{"admin_paths":[{"path":"WinNT://","sid":"S-1-5-21-","class":"User"}],"console_user":"\\"}`,
		"AzureAdJoined : YES\nDomainJoined : YES\nDomainName : \nTenantId : ",
		"alice    console      Feb 29 09:01 \nbob pts/0 2026-02-30 25:61 (tmux(1).%0)\n",
		"alice    tty2         2026-10-22 09:01 (tty2)\n",
		"reboot system boot\nrunlevel (to lvl 5)\nwtmp begins\nalice pts/0",
		"alice console Wed Dec 31 09:01 - 18:00",
		"GroupMembership: root alice", "GroupMembership:",
		"Active Directory Domain = ", "corp\n  configured: kerberos-member\n", "\tconfigured: yes",
		"sudo:x:27:alice,,bob\nwheel:x:10\nadmin::118:", "root:x:0:0::/root:/bin/sh\nbad",
		strings.Repeat("alice ttys000 Jan  3 09:05\n", 200),
	} {
		f.Add(s)
	}

	now := time.Date(2026, 1, 3, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, s string) {
		if p, ok := parseWindowsIdentityProbe(s); ok {
			_ = p.adminMembers()
			_ = p.consoleSession()
			_ = p.windowsJoinFallback()
		}
		_, _ = parseDsregcmd(s)
		_ = windowsLastUser(s)
		_ = isWindowsBuiltinSID(s)
		_ = adsiPathName(s)
		_ = windowsPrincipalSource(s, s, s)
		_ = addConsoleOwner(parseWho(s, now), s)
		_ = parseLastUser(s)
		_, _ = parseDarwinLastLogon(s, "alice", now)
		if names, ok := parseDarwinGroupMembership(s); ok {
			_ = darwinAdminMembers(names, map[string]bool{"alice": true})
		}
		_ = parseDsconfigad(s)
		_ = parseRealmList(s)
		_ = linuxAdminMembers(s, parsePasswdGIDs(s), map[string]bool{"alice": true})
		_ = parseWindowsUsersJSON(s)
	})
}
