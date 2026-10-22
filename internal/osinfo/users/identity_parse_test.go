package users

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

const machineSID = "S-1-5-21-111-222-333"

// TestWindowsAdminMembers_GetLocalGroupMember: a hybrid-joined device's
// Administrators group with a local user, a domain group, an Entra user and
// an Entra role SID.
func TestWindowsAdminMembers_GetLocalGroupMember(t *testing.T) {
	out := `{"admins":[
	  {"name":"PC\\Administrator","sid":"S-1-5-21-111-222-333-500","source":"Local","class":"User"},
	  {"name":"CONTOSO\\Domain Admins","sid":"S-1-5-21-900-901-902-512","source":"ActiveDirectory","class":"Group"},
	  {"name":"AzureAD\\JaneDoe","sid":"S-1-12-1-11-22-33-44","source":"AzureAD","class":"User"},
	  {"name":"S-1-12-1-55-66-77-88","sid":"S-1-12-1-55-66-77-88","source":"Unknown","class":"Group"}
	],"machine_sid":"` + machineSID + `","console_user":"AzureAD\\JaneDoe","part_of_domain":true,"domain":"contoso.com"}`
	p, ok := parseWindowsIdentityProbe(out)
	if !ok {
		t.Fatal("probe didn't parse")
	}
	want := []shared.LocalAdminMember{
		{Name: `AzureAD\JaneDoe`, SID: "S-1-12-1-11-22-33-44", Source: "entra", PrincipalClass: "user"},
		{Name: `CONTOSO\Domain Admins`, SID: "S-1-5-21-900-901-902-512", Source: "domain", PrincipalClass: "group"},
		{Name: `PC\Administrator`, SID: "S-1-5-21-111-222-333-500", Source: "local", PrincipalClass: "user"},
		{Name: "S-1-12-1-55-66-77-88", SID: "S-1-12-1-55-66-77-88", Source: "entra", PrincipalClass: "group"},
	}
	if got := p.adminMembers(); !reflect.DeepEqual(got, want) {
		t.Errorf("adminMembers =\n %+v\nwant\n %+v", got, want)
	}
	if got := p.consoleSession(); !reflect.DeepEqual(got, []shared.SignedInUser{{Username: "JaneDoe", Domain: "AzureAD", Session: "console"}}) {
		t.Errorf("consoleSession = %+v", got)
	}
	if got := p.windowsJoinFallback(); *got != (shared.IdentityJoin{Type: "domain", Domain: "contoso.com"}) {
		t.Errorf("join fallback = %+v", got)
	}
}

// TestWindowsAdminMembers_ADSIFallback: when Get-LocalGroupMember fails,
// names come from the ADSI paths and the source from the SID.
func TestWindowsAdminMembers_ADSIFallback(t *testing.T) {
	out := `{"admin_paths":[
	  {"path":"WinNT://PC/alice","sid":"S-1-5-21-111-222-333-1001","class":"User"},
	  {"path":"WinNT://WORKGROUP/PC/bob","sid":"S-1-5-21-111-222-333-1002","class":"User"},
	  {"path":"WinNT://CONTOSO/jdoe","sid":"S-1-5-21-900-901-902-1105","class":"User"},
	  {"path":"WinNT://S-1-12-1-1-2-3-4","sid":"S-1-12-1-1-2-3-4","class":"User"}
	],"machine_sid":"` + machineSID + `"}`
	p, _ := parseWindowsIdentityProbe(out)
	var got []string
	for _, m := range p.adminMembers() {
		got = append(got, m.Name+"|"+m.Source)
	}
	want := []string{`CONTOSO\jdoe|domain`, `PC\alice|local`, `PC\bob|local`, "S-1-12-1-1-2-3-4|entra"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("members = %q, want %q", got, want)
	}
}

// TestWindowsAdminMembers_Unread: no list from either source is null
// (unknown), an empty group is [] (none).
func TestWindowsAdminMembers_Unread(t *testing.T) {
	p, _ := parseWindowsIdentityProbe(`{"machine_sid":"x"}`)
	if got := p.adminMembers(); got != nil {
		t.Errorf("no list: %+v, want nil", got)
	}
	p, _ = parseWindowsIdentityProbe(`{"admins":[]}`)
	if got := p.adminMembers(); got == nil || len(got) != 0 {
		t.Errorf("empty group: %#v, want []", got)
	}
	if _, ok := parseWindowsIdentityProbe("not json"); ok {
		t.Error("bad JSON parsed")
	}
	if got := (windowsIdentityProbe{}).consoleSession(); got == nil || len(got) != 0 {
		t.Errorf("no console user: %#v, want []", got)
	}
}

func TestWindowsPrincipalSource(t *testing.T) {
	tests := []struct{ source, sid, want string }{
		{"Local", "", "local"},
		{"MicrosoftAccount", "", "local"},
		{"ActiveDirectory", "", "domain"},
		{"AzureAD", "", "entra"},
		{"Unknown", "S-1-12-1-9", "entra"},
		{"", machineSID + "-1001", "local"},
		{"", "S-1-5-21-900-901-902-1105", "domain"},
		{"", "S-1-5-32-545", "local"}, // built-in group
		{"", "S-1-5-4", "local"},      // INTERACTIVE
	}
	for _, tt := range tests {
		if got := windowsPrincipalSource(tt.source, tt.sid, machineSID); got != tt.want {
			t.Errorf("windowsPrincipalSource(%q, %q) = %q, want %q", tt.source, tt.sid, got, tt.want)
		}
	}
}

func TestParseDsregcmd(t *testing.T) {
	const hybrid = `+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+

             AzureAdJoined : YES
          EnterpriseJoined : NO
              DomainJoined : YES
                DomainName : CONTOSO
           Virtual Desktop : NOT SET

+----------------------------------------------------------------------+
| Tenant Details                                                       |
+----------------------------------------------------------------------+

                TenantName : Contoso Ltd
                  TenantId : 7f2c1a00-0000-4000-8000-000000000001
`
	tests := []struct {
		name, out string
		want      *shared.IdentityJoin
	}{
		{"hybrid", hybrid, &shared.IdentityJoin{Type: "hybrid", Domain: "CONTOSO", TenantID: "7f2c1a00-0000-4000-8000-000000000001", TenantName: "Contoso Ltd"}},
		{"entra", "AzureAdJoined : YES\nDomainJoined : NO\nTenantId : t-1\nDomainName : \n", &shared.IdentityJoin{Type: "entra", TenantID: "t-1"}},
		{"domain", "AzureAdJoined : NO\nDomainJoined : YES\nDomainName : CORP\nTenantId : t-1\n", &shared.IdentityJoin{Type: "domain", Domain: "CORP"}},
		{"workgroup", "AzureAdJoined : NO\nDomainJoined : NO\n", &shared.IdentityJoin{Type: "workgroup"}},
	}
	for _, tt := range tests {
		got, ok := parseDsregcmd(tt.out)
		if !ok || !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: parseDsregcmd = %+v, %v; want %+v", tt.name, got, ok, tt.want)
		}
	}
	if _, ok := parseDsregcmd("The command is not recognized"); ok {
		t.Error("unrelated output parsed")
	}
}

func TestWindowsLastUserAndSessionKind(t *testing.T) {
	for in, want := range map[string]string{`.\alice`: "alice", `AzureAD\JaneDoe`: `AzureAD\JaneDoe`, ` CONTOSO\jdoe `: `CONTOSO\jdoe`} {
		if got := windowsLastUser(in); got != want {
			t.Errorf("windowsLastUser(%q) = %q, want %q", in, got, want)
		}
	}
	for proto, want := range map[uint16]string{0: "console", 1: "ica", 2: "rdp"} {
		if got := wtsSessionKind(proto); got != want {
			t.Errorf("wtsSessionKind(%d) = %q, want %q", proto, got, want)
		}
	}
}

func TestParseWho(t *testing.T) {
	now := time.Date(2026, 1, 3, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name, out string
		want      []shared.SignedInUser
	}{
		{
			name: "macOS",
			// Terminal windows add ttys lines; Dec 31 is last year.
			out: "alice    console      Jan  3 09:01 \nalice    ttys000      Jan  3 09:05 \nalice    ttys001      Jan  3 09:02 \nbob      ttys002      Dec 31 22:00 (10.0.0.5)\n",
			want: []shared.SignedInUser{
				{Username: "alice", Session: "console", Since: "2026-01-03T09:01:00Z"},
				{Username: "alice", Session: "terminal", Since: "2026-01-03T09:02:00Z"},
				{Username: "bob", Session: "ssh", Since: "2025-12-31T22:00:00Z"},
			},
		},
		{
			name: "Linux",
			out:  "alice    tty2         2026-01-03 08:00 (tty2)\nalice    pts/1        2026-01-03 08:30 (:0)\nbob      pts/0        2026-01-02 23:15 (host.example.com)\ncarol    pts/2        2026-01-03 11:00\n",
			want: []shared.SignedInUser{
				{Username: "alice", Session: "console", Since: "2026-01-03T08:00:00Z"},
				{Username: "bob", Session: "ssh", Since: "2026-01-02T23:15:00Z"},
				{Username: "carol", Session: "terminal", Since: "2026-01-03T11:00:00Z"},
			},
		},
		{name: "nobody", out: "", want: []shared.SignedInUser{}},
	}
	for _, tt := range tests {
		if got := parseWho(tt.out, now); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: parseWho =\n %+v\nwant\n %+v", tt.name, got, tt.want)
		}
	}
}

func TestAddConsoleOwner(t *testing.T) {
	if got := addConsoleOwner([]shared.SignedInUser{}, "alice\n"); !reflect.DeepEqual(got, []shared.SignedInUser{{Username: "alice", Session: "console"}}) {
		t.Errorf("added = %+v", got)
	}
	if got := addConsoleOwner([]shared.SignedInUser{}, "root"); len(got) != 0 {
		t.Errorf("login window (root) added: %+v", got)
	}
	has := []shared.SignedInUser{{Username: "alice", Session: "console"}}
	if got := addConsoleOwner(has, "bob"); len(got) != 1 {
		t.Errorf("second console session added: %+v", got)
	}
}

func TestParseLastUser(t *testing.T) {
	out := "reboot   system boot  6.8.0-45-generic Fri Jan  2 08:00   still running\nalice    pts/0        10.0.0.5         Fri Jan  2 09:00   still logged in\n\nwtmp begins Thu Jan  1 00:00:01 2026\n"
	if got := parseLastUser(out); got != "alice" {
		t.Errorf("parseLastUser = %q, want alice", got)
	}
	if got := parseLastUser("\nwtmp begins Thu Jan  1 00:00:01 2026\n"); got != "" {
		t.Errorf("empty log = %q", got)
	}
}

func TestParseDarwinLastLogon(t *testing.T) {
	now := time.Date(2026, 1, 3, 12, 0, 0, 0, time.UTC)
	got, ok := parseDarwinLastLogon("alice     console                   Wed Dec 31 09:01 - 18:00  (08:59)\n\nwtmp begins Mon Dec  1 08:00\n", "alice", now)
	if !ok || !got.Equal(time.Date(2025, 12, 31, 9, 1, 0, 0, time.UTC)) {
		t.Errorf("last logon = %v, %v", got, ok)
	}
	if _, ok := parseDarwinLastLogon("\nwtmp begins Mon Dec  1 08:00\n", "alice", now); ok {
		t.Error("no record parsed")
	}
	// A record for another user whose name starts the same doesn't count.
	if _, ok := parseDarwinLastLogon("alicebob  console  Wed Dec 31 09:01   still logged in\n", "alice", now); ok {
		t.Error("other user's record counted")
	}
}

func TestDarwinAdminMembers(t *testing.T) {
	names, ok := parseDarwinGroupMembership("GroupMembership: root alice jdoe\n")
	if !ok {
		t.Fatal("not parsed")
	}
	got := darwinAdminMembers(names, map[string]bool{"root": true, "alice": true})
	want := []shared.LocalAdminMember{
		{Name: "alice", Source: "local", PrincipalClass: "user"},
		{Name: "jdoe", Source: "domain", PrincipalClass: "user"}, // from a bound directory
		{Name: "root", Source: "local", PrincipalClass: "user"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("members = %+v", got)
	}
	if _, ok := parseDarwinGroupMembership("No such key: GroupMembership"); ok {
		t.Error("missing key parsed")
	}
}

func TestParseDsconfigad(t *testing.T) {
	bound := "Active Directory Forest          = corp.example.com\nActive Directory Domain          = corp.example.com\nComputer Account                 = mac01$\n"
	if got := parseDsconfigad(bound); *got != (shared.IdentityJoin{Type: "domain", Domain: "corp.example.com"}) {
		t.Errorf("bound = %+v", got)
	}
	if got := parseDsconfigad(""); got.Type != "workgroup" {
		t.Errorf("unbound = %+v", got)
	}
}

func TestParseRealmList(t *testing.T) {
	out := "corp.example.com\n  type: kerberos\n  realm-name: CORP.EXAMPLE.COM\n  configured: kerberos-member\n  server-software: active-directory\n"
	if got := parseRealmList(out); *got != (shared.IdentityJoin{Type: "domain", Domain: "corp.example.com"}) {
		t.Errorf("joined = %+v", got)
	}
	if got := parseRealmList("other.example\n  type: kerberos\n  configured: no\n"); got.Type != "workgroup" {
		t.Errorf("discovered but not joined = %+v", got)
	}
	if got := parseRealmList(""); got.Type != "workgroup" {
		t.Errorf("none = %+v", got)
	}
}

func TestLinuxAdminMembers(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nops:x:1001:10::/home/ops:/bin/bash\nbob:x:1002:1002::/home/bob:/bin/bash\n"
	groups := "sudo:x:27:alice,jdoe@corp.example.com\nwheel:x:10:\nadmin:x:118:\nusers:x:100:bob\n"
	got := linuxAdminMembers(groups, parsePasswdGIDs(passwd), map[string]bool{"root": true, "alice": true, "ops": true, "bob": true})
	want := []shared.LocalAdminMember{
		{Name: "alice", Source: "local", PrincipalClass: "user"},
		{Name: "jdoe@corp.example.com", Source: "domain", PrincipalClass: "user"}, // sssd user
		{Name: "ops", Source: "local", PrincipalClass: "user"},                    // primary group wheel
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("members =\n %+v\nwant\n %+v", got, want)
	}
	if got := linuxAdminMembers("users:x:100:bob\n", nil, nil); got == nil || len(got) != 0 {
		t.Errorf("no admin groups = %#v, want []", got)
	}
}

// TestUserIdentityJSON: lists that couldn't be read are null, empty lists
// are [], and the optional keys are left out.
func TestUserIdentityJSON(t *testing.T) {
	b, _ := json.Marshal(shared.UserIdentity{SignedInUsers: []shared.SignedInUser{}})
	if want := `{"local_admin_members":null,"signed_in_users":[]}`; string(b) != want {
		t.Errorf("json = %s, want %s", b, want)
	}
}
