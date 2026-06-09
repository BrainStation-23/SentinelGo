package users

// users_test.go has no OS-specific file suffix, so every test runs on every
// platform. All functions under test live in parse.go which is also suffix-free.

import (
	"testing"
)

// ── parsePasswdContent ────────────────────────────────────────────────────────

const passwdSample = `# /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
john:x:1000:1000:John Doe,,,:/home/john:/bin/bash
jane:x:1001:1001::/home/jane:/bin/zsh
svc:x:1002:1002:Service Account:/home/svc:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
`

func TestParsePasswdContent(t *testing.T) {
	users := parsePasswdContent(passwdSample)

	// root, daemon, _apt, nobody, systemd-network are filtered; john, jane, svc pass
	if len(users) != 3 {
		t.Fatalf("expected 3 users, got %d: %+v", len(users), users)
	}

	cases := []struct {
		username, uid, gid, homeDir, shell string
	}{
		{"john", "1000", "1000", "/home/john", "/bin/bash"},
		{"jane", "1001", "1001", "/home/jane", "/bin/zsh"},
		{"svc", "1002", "1002", "/home/svc", "/bin/false"},
	}
	for i, c := range cases {
		u := users[i]
		if u.Username != c.username {
			t.Errorf("[%d] Username = %q, want %q", i, u.Username, c.username)
		}
		if u.UID != c.uid {
			t.Errorf("[%d] UID = %q, want %q", i, u.UID, c.uid)
		}
		if u.GID != c.gid {
			t.Errorf("[%d] GID = %q, want %q", i, u.GID, c.gid)
		}
		if u.HomeDir != c.homeDir {
			t.Errorf("[%d] HomeDir = %q, want %q", i, u.HomeDir, c.homeDir)
		}
		if u.Shell != c.shell {
			t.Errorf("[%d] Shell = %q, want %q", i, u.Shell, c.shell)
		}
		if u.Groups != nil {
			t.Errorf("[%d] Groups should be nil from parse (filled by caller), got %v", i, u.Groups)
		}
	}
}

func TestParsePasswdContent_Empty(t *testing.T) {
	if got := parsePasswdContent(""); len(got) != 0 {
		t.Errorf("expected 0 users for empty input, got %d", len(got))
	}
}

func TestParsePasswdContent_CommentsAndShortLines(t *testing.T) {
	input := "# comment line\njohn:x:1000:1000::/home/john:/bin/bash\nmalformed\n"
	users := parsePasswdContent(input)
	if len(users) != 1 || users[0].Username != "john" {
		t.Errorf("expected only john, got %+v", users)
	}
}

func TestParsePasswdContent_RootExcluded(t *testing.T) {
	input := "root:x:0:0:root:/home/root:/bin/bash\n"
	if got := parsePasswdContent(input); len(got) != 0 {
		t.Errorf("root should be excluded, got %+v", got)
	}
}

func TestParsePasswdContent_NoHomeDirFilter(t *testing.T) {
	cases := []struct {
		line    string
		include bool
	}{
		{"bob:x:1000:1000::/home/bob:/bin/bash", true},
		{"bob:x:1000:1000:::/bin/bash", false},         // empty homeDir
		{"bob:x:1000:1000::/:/bin/bash", false},        // homeDir is /
		{"bob:x:1000:1000::/var/bob:/bin/bash", false}, // not under /home/
		{"bob:x:1000:1000::/home/bob:/bin/bash", true}, // valid /home/ prefix
	}
	for _, c := range cases {
		got := parsePasswdContent(c.line)
		if c.include && len(got) == 0 {
			t.Errorf("line %q should be included but was filtered", c.line)
		}
		if !c.include && len(got) != 0 {
			t.Errorf("line %q should be filtered but was included", c.line)
		}
	}
}

func TestParsePasswdContent_CRLFShell(t *testing.T) {
	// Shell field should have trailing \r stripped (defensive against CRLF files)
	input := "john:x:1000:1000::/home/john:/bin/bash\r\n"
	users := parsePasswdContent(input)
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if users[0].Shell != "/bin/bash" {
		t.Errorf("Shell = %q, want %q (\\r should be stripped)", users[0].Shell, "/bin/bash")
	}
}

// ── parseLinuxGroupOutput ─────────────────────────────────────────────────────

func TestParseLinuxGroupOutput(t *testing.T) {
	cases := []struct {
		desc     string
		output   string
		username string
		want     []string
	}{
		{
			desc:     "GNU coreutils format with space-colon-space prefix",
			output:   "john : john adm cdrom sudo docker",
			username: "john",
			want:     []string{"john", "adm", "cdrom", "sudo", "docker"},
		},
		{
			desc:     "format without prefix (some distros)",
			output:   "adm cdrom sudo docker",
			username: "john",
			want:     []string{"adm", "cdrom", "sudo", "docker"},
		},
		{
			desc:     "colon-space without space before colon",
			output:   "jane: audio video plugdev",
			username: "jane",
			want:     []string{"audio", "video", "plugdev"},
		},
		{
			desc:     "single group",
			output:   "bob : bob",
			username: "bob",
			want:     []string{"bob"},
		},
		{
			desc:     "empty output",
			output:   "",
			username: "alice",
			want:     nil,
		},
	}
	for _, c := range cases {
		got := parseLinuxGroupOutput(c.output, c.username)
		if len(got) != len(c.want) {
			t.Errorf("[%s] len = %d, want %d: got %v", c.desc, len(got), len(c.want), got)
			continue
		}
		for i, g := range got {
			if g != c.want[i] {
				t.Errorf("[%s] groups[%d] = %q, want %q", c.desc, i, g, c.want[i])
			}
		}
	}
}

func TestParseLinuxGroupOutput_UsernameNotStrippedWhenNoPrefix(t *testing.T) {
	// If username appears as an actual group (user's own group) without a prefix,
	// it should be kept — we only strip the "username :" header.
	got := parseLinuxGroupOutput("john adm sudo", "john")
	if len(got) != 3 || got[0] != "john" {
		t.Errorf("expected [john adm sudo], got %v", got)
	}
}

// ── parseDarwinUserList ───────────────────────────────────────────────────────

const darwinUserListSample = `_amavisd
_jabber
_locationd
daemon
Guest
john
jane
nobody
root
`

func TestParseDarwinUserList(t *testing.T) {
	result := parseDarwinUserList(darwinUserListSample)

	if len(result) != 2 {
		t.Fatalf("expected 2 users, got %d: %v", len(result), result)
	}
	if result[0] != "john" || result[1] != "jane" {
		t.Errorf("expected [john jane], got %v", result)
	}
}

func TestParseDarwinUserList_Empty(t *testing.T) {
	if got := parseDarwinUserList(""); len(got) != 0 {
		t.Errorf("expected 0 users for empty input, got %d", len(got))
	}
}

func TestParseDarwinUserList_AllFiltered(t *testing.T) {
	input := "_service\ndaemon\nroot\nGuest\nnobody\n"
	if got := parseDarwinUserList(input); len(got) != 0 {
		t.Errorf("expected all accounts filtered, got %v", got)
	}
}

// ── parseDarwinProperty ───────────────────────────────────────────────────────

func TestParseDarwinProperty(t *testing.T) {
	cases := []struct {
		input, want string
	}{
		{"UniqueID: 501", "501"},
		{"UserShell: /bin/zsh", "/bin/zsh"},
		{"NFSHomeDirectory: /Users/john", "/Users/john"},
		// Multi-line form: value on the next line (dscl sometimes does this)
		{"NFSHomeDirectory:\n /Users/john", "/Users/john"},
		// No colon → empty
		{"NoColonHere", ""},
		// Empty value
		{"PrimaryGroupID: ", ""},
		// Empty input
		{"", ""},
	}
	for _, c := range cases {
		got := parseDarwinProperty(c.input)
		if got != c.want {
			t.Errorf("parseDarwinProperty(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

// ── parseDarwinIDGroups ───────────────────────────────────────────────────────

func TestParseDarwinIDGroups(t *testing.T) {
	input := "staff everyone localaccounts _appserverusr admin _lpadmin\n"
	got := parseDarwinIDGroups(input)
	want := []string{"staff", "everyone", "localaccounts", "_appserverusr", "admin", "_lpadmin"}
	if len(got) != len(want) {
		t.Fatalf("expected %d groups, got %d: %v", len(want), len(got), got)
	}
	for i, g := range got {
		if g != want[i] {
			t.Errorf("groups[%d] = %q, want %q", i, g, want[i])
		}
	}
}

func TestParseDarwinIDGroups_Empty(t *testing.T) {
	if got := parseDarwinIDGroups(""); len(got) != 0 {
		t.Errorf("expected 0 groups for empty input, got %d", len(got))
	}
}

// ── parseWindowsUsersJSON ─────────────────────────────────────────────────────

const winUsersArray = `[
  {"Name": "john",               "SID": "S-1-5-21-111-1000"},
  {"Name": "Administrator",      "SID": "S-1-5-21-111-500"},
  {"Name": "Guest",              "SID": "S-1-5-21-111-501"},
  {"Name": "DefaultAccount",     "SID": "S-1-5-21-111-503"},
  {"Name": "WDAGUtilityAccount", "SID": "S-1-5-21-111-504"},
  {"Name": "defaultuser0",       "SID": "S-1-5-21-111-1002"},
  {"Name": "jane",               "SID": "S-1-5-21-111-1001"}
]`

const winUsersSingle = `{"Name": "john", "SID": "S-1-5-21-111-1000"}`

func TestParseWindowsUsersJSON_Array(t *testing.T) {
	users := parseWindowsUsersJSON(winUsersArray)

	if len(users) != 2 {
		t.Fatalf("expected 2 non-system users, got %d: %+v", len(users), users)
	}
	if users[0].Username != "john" || users[0].UID != "S-1-5-21-111-1000" {
		t.Errorf("users[0] = %+v, want john/S-1-5-21-111-1000", users[0])
	}
	if users[1].Username != "jane" || users[1].UID != "S-1-5-21-111-1001" {
		t.Errorf("users[1] = %+v, want jane/S-1-5-21-111-1001", users[1])
	}
}

func TestParseWindowsUsersJSON_Single(t *testing.T) {
	// PowerShell returns a bare object (not array) when there is exactly one user.
	users := parseWindowsUsersJSON(winUsersSingle)
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if users[0].Username != "john" {
		t.Errorf("Username = %q, want john", users[0].Username)
	}
}

func TestParseWindowsUsersJSON_SystemAccountsFiltered(t *testing.T) {
	cases := []struct {
		name    string
		exclude bool
	}{
		{"Administrator", true},
		{"administrator", true}, // case-insensitive
		{"Guest", true},
		{"DefaultAccount", true},
		{"WDAGUtilityAccount", true},
		{"defaultuser0", true},
		{"defaultuser1", true},
		{"john", false},
		{"Alice", false},
	}
	for _, c := range cases {
		input := `[{"Name": "` + c.name + `", "SID": "S-1-5-21-0"}]`
		got := parseWindowsUsersJSON(input)
		if c.exclude && len(got) != 0 {
			t.Errorf("%q should be excluded but was returned", c.name)
		}
		if !c.exclude && len(got) != 1 {
			t.Errorf("%q should be included but was filtered", c.name)
		}
	}
}

func TestParseWindowsUsersJSON_Invalid(t *testing.T) {
	if got := parseWindowsUsersJSON("not json"); got != nil {
		t.Errorf("expected nil for invalid JSON, got %+v", got)
	}
}

func TestParseWindowsUsersJSON_MissingName(t *testing.T) {
	input := `[{"SID": "S-1-5-21-0"}, {"Name": "john", "SID": "S-1-5-21-1"}]`
	got := parseWindowsUsersJSON(input)
	if len(got) != 1 || got[0].Username != "john" {
		t.Errorf("expected only john (row without Name skipped), got %+v", got)
	}
}

// ── parseWindowsGroupLines ────────────────────────────────────────────────────

func TestParseWindowsGroupLines(t *testing.T) {
	input := "Administrators\r\nUsers\r\nRemote Desktop Users\r\n"
	got := parseWindowsGroupLines(input)
	want := []string{"Administrators", "Users", "Remote Desktop Users"}
	if len(got) != len(want) {
		t.Fatalf("expected %d groups, got %d: %v", len(want), len(got), got)
	}
	for i, g := range got {
		if g != want[i] {
			t.Errorf("groups[%d] = %q, want %q", i, g, want[i])
		}
	}
}

func TestParseWindowsGroupLines_BlankLines(t *testing.T) {
	input := "\nAdministrators\n\nUsers\n"
	got := parseWindowsGroupLines(input)
	if len(got) != 2 {
		t.Errorf("expected 2 groups (blank lines skipped), got %d: %v", len(got), got)
	}
}

func TestParseWindowsGroupLines_Empty(t *testing.T) {
	if got := parseWindowsGroupLines(""); len(got) != 0 {
		t.Errorf("expected 0 groups for empty input, got %d", len(got))
	}
}

// ── integration ───────────────────────────────────────────────────────────────

func TestGet_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live user collection (shells out to OS commands) in -short mode")
	}

	users := Get()
	t.Logf("Get() returned %d user(s)", len(users))
	for i, u := range users {
		t.Logf("  [%d] username=%q uid=%q gid=%q home=%q shell=%q groups=%v",
			i, u.Username, u.UID, u.GID, u.HomeDir, u.Shell, u.Groups)
		if u.Username == "" {
			t.Errorf("users[%d].Username is empty", i)
		}
	}
}
