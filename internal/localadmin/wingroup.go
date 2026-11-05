package localadmin

// Windows: the Administrators group, always by its SID (S-1-5-32-544), whose
// name is localized. PowerShell only lists and changes the group; matching
// and every guard are here, in Go, where they are tested. Account names
// reach PowerShell through environment variables, never as script text.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// winListScript lists the Administrators group with whether each local user
// is enabled. Get-LocalGroupMember fails when the group holds a member it
// can't resolve (a deleted Entra account); the error is then returned.
const winListScript = `$ErrorActionPreference = 'Stop'
$out = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object {
  $en = $true
  if ("$($_.PrincipalSource)" -eq 'Local' -and "$($_.ObjectClass)" -eq 'User') {
    $u = Get-LocalUser -SID $_.SID -ErrorAction SilentlyContinue
    if ($u) { $en = [bool]$u.Enabled }
  }
  [pscustomobject]@{ name = "$($_.Name)"; sid = "$($_.SID.Value)"; source = "$($_.PrincipalSource)"; class = "$($_.ObjectClass)"; enabled = $en }
})
ConvertTo-Json -InputObject $out -Compress`

// winAddScript adds SG_TARGET. Add-LocalGroupMember fails on some AzureAD\
// names; net localgroup, with the group's localized name, works then.
const winAddScript = `$ErrorActionPreference = 'Stop'
try {
  Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $env:SG_TARGET
} catch {
  $group = (Get-LocalGroup -SID 'S-1-5-32-544').Name
  & "$env:SystemRoot\System32\net.exe" localgroup $group $env:SG_TARGET /add | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Couldn't add $($env:SG_TARGET): $($_.Exception.Message)" }
}`

// winRemoveScript removes the member with SID SG_SID.
const winRemoveScript = `$ErrorActionPreference = 'Stop'
Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $env:SG_SID`

func powershell(ctx context.Context, run Runner, script string, env ...string) (string, error) {
	return run(ctx, "powershell", []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script}, env)
}

// winMember is one row of winListScript.
type winMember struct {
	Name    string `json:"name"`
	SID     string `json:"sid"`
	Source  string `json:"source"` // Local, ActiveDirectory, AzureAD, MicrosoftAccount, Unknown
	Class   string `json:"class"`  // User, Group
	Enabled bool   `json:"enabled"`
}

type windowsGroup struct {
	run     Runner
	signOut func(ctx context.Context, user string) (int, error)
}

// target is what Add-LocalGroupMember is given: the SID when known, an
// Entra account as AzureAD\name, else the name as sent.
func winTarget(r Request) string {
	switch {
	case r.SID != "":
		return r.SID
	case r.Source == "entra" && !strings.Contains(r.Member, `\`):
		return `AzureAD\` + r.Member
	}
	return r.Member
}

func (g *windowsGroup) members(ctx context.Context) ([]winMember, error) {
	out, err := powershell(ctx, g.run, winListScript)
	if err != nil {
		return nil, fmt.Errorf("couldn't list the administrators: %w", err)
	}
	var m []winMember
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &m); err != nil {
		return nil, fmt.Errorf("couldn't list the administrators: unreadable output")
	}
	return m, nil
}

// winMatch finds the request's account: by SID; else, for a local account,
// a local member with the same bare name; else the full name. So local
// "bob" and "CONTOSO\bob" are never the same account.
func winMatch(members []winMember, r Request) *winMember {
	target, bare := winTarget(r), bareName(r.Member)
	for i := range members {
		x := &members[i]
		switch {
		case r.SID != "":
			if strings.EqualFold(x.SID, r.SID) {
				return x
			}
		case r.Source == "" || r.Source == "local":
			if strings.EqualFold(x.Source, "Local") && strings.EqualFold(bareName(x.Name), bare) {
				return x
			}
		default:
			if strings.EqualFold(x.Name, target) {
				return x
			}
		}
	}
	return nil
}

func isBuiltinAdminSID(sid string) bool {
	return strings.HasPrefix(sid, "S-1-5-21-") && strings.HasSuffix(sid, "-500")
}

func isSystemSID(sid string) bool {
	return sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20"
}

func (g *windowsGroup) IsMember(ctx context.Context, r Request) (bool, error) {
	m, err := g.members(ctx)
	if err != nil {
		return false, err
	}
	return winMatch(m, r) != nil, nil
}

func (g *windowsGroup) Add(ctx context.Context, r Request) (Outcome, error) {
	target := winTarget(r)
	// as in the script, a group that can't be listed doesn't stop an add
	if m, err := g.members(ctx); err == nil {
		if winMatch(m, r) != nil {
			return Outcome{Success: true, State: StateAlready, Member: target}, nil
		}
	}
	if _, err := powershell(ctx, g.run, winAddScript, "SG_TARGET="+target); err != nil {
		return Outcome{}, fmt.Errorf("couldn't add %s: %w", target, err)
	}
	return Outcome{Success: true, State: StateAdded, Member: target}, nil
}

func (g *windowsGroup) Remove(ctx context.Context, r Request) (Outcome, error) {
	members, err := g.members(ctx)
	if err != nil {
		return Outcome{}, err
	}
	m := winMatch(members, r)
	if m == nil {
		return Outcome{Success: true, State: StateAbsent, Member: winTarget(r)}, nil
	}
	switch {
	case isBuiltinAdminSID(m.SID):
		return Outcome{}, ErrBuiltinAdmin
	case isSystemSID(m.SID):
		return Outcome{}, ErrSystemAccount
	}
	// the last enabled administrator stays: other enabled users, not
	// counting the built-in Administrator (a directory user counts as enabled)
	others := 0
	for _, x := range members {
		if x.SID == m.SID || !strings.EqualFold(x.Class, "User") || strings.HasSuffix(x.SID, "-500") {
			continue
		}
		if strings.EqualFold(x.Source, "Local") && !x.Enabled {
			continue
		}
		others++
	}
	if others == 0 {
		return Outcome{}, lastAdminError(m.Name)
	}
	if _, err := powershell(ctx, g.run, winRemoveScript, "SG_SID="+m.SID); err != nil {
		return Outcome{}, fmt.Errorf("couldn't remove %s: %w", m.Name, err)
	}
	out := Outcome{Success: true, State: StateRemoved, Member: m.Name}
	n := 0
	if r.SignOut && g.signOut != nil {
		n, _ = g.signOut(ctx, bareName(m.Name))
	}
	out.SignedOut = &n
	return out, nil
}
