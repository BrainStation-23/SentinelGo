//go:build linux

package users

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

// stubLinux makes the collectors see only the given command outputs (keyed
// by the space-joined command line) and files; anything else fails.
func stubLinux(t *testing.T, cmds, files map[string]string) {
	t.Helper()
	origRun, origOut, origRead, origLookup := runCommand, runCommandOutput, readFile, lookupBinary
	t.Cleanup(func() { runCommand, runCommandOutput, readFile, lookupBinary = origRun, origOut, origRead, origLookup })
	run := func(name string, args ...string) (string, error) {
		if out, ok := cmds[strings.Join(append([]string{name}, args...), " ")]; ok {
			return out, nil
		}
		return "", errors.New("not installed")
	}
	runCommand = run
	runCommandOutput = func(name string, args ...string) (string, int, error) {
		out, err := run(name, args...)
		if err != nil {
			return "", -1, err
		}
		return out, 2, nil // getent's "some group not found"
	}
	readFile = func(path string) (string, error) {
		if c, ok := files[path]; ok {
			return c, nil
		}
		return "", errors.New("no such file")
	}
	lookupBinary = func(name string) (string, error) { return "/fixed/" + name, nil }
}

const linuxPasswd = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"

func TestGetIdentity_Linux(t *testing.T) {
	stubLinux(t, map[string]string{
		// A directory account whose primary group is sudo (GID 27), seen
		// only through NSS.
		"getent passwd":                 linuxPasswd + "jdoe@corp:*:1500:27:John:/home/jdoe:/bin/bash\n",
		"getent group sudo wheel admin": "sudo:x:27:alice\n",
		"env LC_ALL=C /fixed/who":       "alice    pts/0        2026-10-22 10:15 (10.0.0.5)\n",
		"last -w -n 20":                 "runlevel (to lvl 5)   6.8.0  Wed Oct 22 08:00   still running\nalice    pts/0        10.0.0.5   Wed Oct 22 10:15   still logged in\n",
		"realm list":                    "corp.example.com\n  configured: kerberos-member\n",
	}, map[string]string{"/etc/passwd": linuxPasswd})

	id := getIdentity()
	wantAdmins := []shared.LocalAdminMember{
		{Name: "alice", Source: "local", PrincipalClass: "user"},
		{Name: "jdoe@corp", Source: "domain", PrincipalClass: "user"},
	}
	if !reflect.DeepEqual(id.AdminMembers, wantAdmins) {
		t.Errorf("AdminMembers = %+v, want %+v", id.AdminMembers, wantAdmins)
	}
	if len(id.SignedInUsers) != 1 || id.SignedInUsers[0].Username != "alice" || id.SignedInUsers[0].Session != "ssh" {
		t.Errorf("SignedInUsers = %+v", id.SignedInUsers)
	}
	if id.LastSignedInUser != "alice" {
		t.Errorf("LastSignedInUser = %q, want alice (runlevel isn't a user)", id.LastSignedInUser)
	}
	if id.Join == nil || *id.Join != (shared.IdentityJoin{Type: "domain", Domain: "corp.example.com"}) {
		t.Errorf("Join = %+v", id.Join)
	}
}

func TestGetIdentity_LinuxFallbacks(t *testing.T) {
	// No getent: /etc/group and /etc/passwd are read instead. No who, last
	// or realm: those fields are left unknown.
	stubLinux(t, nil, map[string]string{
		"/etc/passwd": linuxPasswd + "ops:x:1001:10::/home/ops:/bin/bash\n",
		"/etc/group":  "sudo:x:27:alice\nwheel:x:10:\n",
	})
	id := getIdentity()
	var names []string
	for _, m := range id.AdminMembers {
		names = append(names, m.Name)
	}
	if !reflect.DeepEqual(names, []string{"alice", "ops"}) {
		t.Errorf("admins = %q, want alice and ops (primary group wheel)", names)
	}
	if id.SignedInUsers != nil || id.LastSignedInUser != "" || id.Join != nil {
		t.Errorf("unread fields = %+v, want unknown", id)
	}

	// Without the account records the roster is unknown, not empty.
	stubLinux(t, nil, nil)
	if got := linuxAdminRoster(); got != nil {
		t.Errorf("no passwd: %+v, want nil", got)
	}
	stubLinux(t, nil, map[string]string{"/etc/passwd": linuxPasswd})
	if got := linuxAdminRoster(); got != nil {
		t.Errorf("no group records: %+v, want nil", got)
	}
}
