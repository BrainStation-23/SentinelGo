package users

import (
	"errors"
	"reflect"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

// stubWindows makes the PowerShell probe return probe and dsregcmd return
// dsreg (an error when empty). Sessions and the LogonUI value are read from
// the real machine.
func stubWindows(t *testing.T, probe, dsreg string) {
	t.Helper()
	origPS, origRun := runPowerShell, runCommand
	t.Cleanup(func() { runPowerShell, runCommand = origPS, origRun })
	runPowerShell = func(script string) (string, error) {
		if script == identityScript && probe != "" {
			return probe, nil
		}
		return "", errors.New("powershell failed")
	}
	runCommand = func(name string, args ...string) (string, error) {
		if name == "dsregcmd" && dsreg != "" {
			return dsreg, nil
		}
		return "", errors.New("not available")
	}
}

func TestGetIdentity_Windows(t *testing.T) {
	stubWindows(t,
		`{"admins":[{"name":"AzureAD\\JaneDoe","sid":"S-1-12-1-1-2-3-4","source":"AzureAD","class":"User"}],"machine_sid":"S-1-5-21-1-2-3"}`,
		"AzureAdJoined : YES\nDomainJoined : NO\nTenantId : t-1\n")
	id := getIdentity()
	want := []shared.LocalAdminMember{{Name: `AzureAD\JaneDoe`, SID: "S-1-12-1-1-2-3-4", Source: "entra", PrincipalClass: "user"}}
	if !reflect.DeepEqual(id.AdminMembers, want) {
		t.Errorf("AdminMembers = %+v", id.AdminMembers)
	}
	if id.Join == nil || *id.Join != (shared.IdentityJoin{Type: "entra", TenantID: "t-1"}) {
		t.Errorf("Join = %+v", id.Join)
	}
	if id.SignedInUsers == nil {
		t.Error("SignedInUsers = nil; the session list should be readable on any Windows host")
	}
}

func TestGetIdentity_WindowsFallbacks(t *testing.T) {
	// No dsregcmd: Win32_ComputerSystem says whether it's in a domain.
	stubWindows(t, `{"admins":[],"part_of_domain":true,"domain":"corp.example.com"}`, "")
	id := getIdentity()
	if id.AdminMembers == nil || len(id.AdminMembers) != 0 {
		t.Errorf("AdminMembers = %#v, want []", id.AdminMembers)
	}
	if id.Join == nil || *id.Join != (shared.IdentityJoin{Type: "domain", Domain: "corp.example.com"}) {
		t.Errorf("Join = %+v", id.Join)
	}

	// Nothing readable: admins and join are unknown.
	stubWindows(t, "", "")
	id = getIdentity()
	if id.AdminMembers != nil || id.Join != nil {
		t.Errorf("unread = %+v, want unknown", id)
	}
}
