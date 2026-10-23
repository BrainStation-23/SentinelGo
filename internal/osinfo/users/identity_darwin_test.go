//go:build darwin

package users

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

// stubDarwin makes runCommand return the given outputs (keyed by the
// space-joined command line); anything else fails.
func stubDarwin(t *testing.T, cmds map[string]string) {
	t.Helper()
	orig := runCommand
	t.Cleanup(func() { runCommand = orig })
	runCommand = func(name string, args ...string) (string, error) {
		if out, ok := cmds[strings.Join(append([]string{name}, args...), " ")]; ok {
			return out, nil
		}
		return "", errors.New("command failed")
	}
}

func TestGetIdentity_Darwin(t *testing.T) {
	stubDarwin(t, map[string]string{
		"dscl . read /Groups/admin GroupMembership": "GroupMembership: root alice jdoe\n",
		"dscl . list /Users":                        "_spotlight\nalice\nroot\n",
		"who":                                       "bob      ttys001      Jan  3 09:01 (10.0.0.5)\n",
		"stat -f %Su /dev/console":                  "alice\n",
		"defaults read /Library/Preferences/com.apple.loginwindow lastUserName": "alice\n",
		"dsconfigad -show": "",
	})
	id := getIdentity()
	want := []shared.LocalAdminMember{
		{Name: "alice", Source: "local", PrincipalClass: "user"},
		{Name: "jdoe", Source: "domain", PrincipalClass: "user"},
		{Name: "root", Source: "local", PrincipalClass: "user"},
	}
	if !reflect.DeepEqual(id.AdminMembers, want) {
		t.Errorf("AdminMembers = %+v", id.AdminMembers)
	}
	var sessions []string
	for _, u := range id.SignedInUsers {
		sessions = append(sessions, u.Username+"/"+u.Session)
	}
	if !reflect.DeepEqual(sessions, []string{"bob/ssh", "alice/console"}) {
		t.Errorf("sessions = %q", sessions)
	}
	if id.LastSignedInUser != "alice" || id.Join == nil || id.Join.Type != "workgroup" {
		t.Errorf("last = %q, join = %+v", id.LastSignedInUser, id.Join)
	}
}

// TestDarwinAdminRoster_Unreadable: when the local account list can't be
// read, local admins can't be told from directory ones, so the roster is
// unknown rather than all "domain".
func TestDarwinAdminRoster_Unreadable(t *testing.T) {
	stubDarwin(t, map[string]string{"dscl . read /Groups/admin GroupMembership": "GroupMembership: root alice\n"})
	if got := darwinAdminRoster(); got != nil {
		t.Errorf("roster = %+v, want nil", got)
	}
	stubDarwin(t, map[string]string{"dscl . read /Groups/admin GroupMembership": "No such key: GroupMembership\n"})
	if got := darwinAdminRoster(); got != nil {
		t.Errorf("roster = %+v, want nil", got)
	}
}

func TestDarwinLastLogon(t *testing.T) {
	stubDarwin(t, map[string]string{"last -1 alice": "alice     console                   Wed Jan  1 09:01 - 18:00  (08:59)\n"})
	if got := darwinLastLogon("alice"); got == nil {
		t.Error("last logon not read")
	}
	if got := darwinLastLogon("bob"); got != nil {
		t.Errorf("no record: %+v, want nil", got)
	}
}
