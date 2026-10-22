package users

// Parsers for the identity fields (#223): local admin members, signed-in
// users, the last signed-in user, directory join and macOS last logon. No OS
// suffix, so they are tested on every platform.

import (
	"encoding/json"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

// ── Windows ───────────────────────────────────────────────────────────────────

// windowsBuiltinRIDs are the relative IDs of the accounts Windows creates:
// Administrator, Guest, DefaultAccount and WDAGUtilityAccount.
var windowsBuiltinRIDs = []string{"-500", "-501", "-503", "-504"}

// isWindowsBuiltinSID reports whether sid is one of a machine's built-in
// accounts. They are matched by RID, so a renamed Administrator still counts.
func isWindowsBuiltinSID(sid string) bool {
	if !strings.HasPrefix(sid, "S-1-5-21-") {
		return false
	}
	for _, rid := range windowsBuiltinRIDs {
		if strings.HasSuffix(sid, rid) {
			return true
		}
	}
	return false
}

// windowsIdentityProbe is the output of the users_windows.go identity
// script. Admins comes from Get-LocalGroupMember; AdminPaths from the ADSI
// fallback used when that cmdlet fails (it does when the group holds a SID
// it can't resolve, common on Entra-joined devices).
type windowsIdentityProbe struct {
	Admins       []windowsAdminRow `json:"admins"`
	AdminPaths   []windowsAdminRow `json:"admin_paths"`
	MachineSID   string            `json:"machine_sid"`
	ConsoleUser  string            `json:"console_user"`
	PartOfDomain bool              `json:"part_of_domain"`
	Domain       string            `json:"domain"`
}

type windowsAdminRow struct {
	Name   string `json:"name"`
	Path   string `json:"path"` // ADSI: WinNT://DOMAIN/user or WinNT://WORKGROUP/PC/user
	SID    string `json:"sid"`
	Source string `json:"source"` // PrincipalSource: Local, ActiveDirectory, AzureAD, MicrosoftAccount, Unknown
	Class  string `json:"class"`  // User or Group
}

func parseWindowsIdentityProbe(out string) (windowsIdentityProbe, bool) {
	var p windowsIdentityProbe
	if json.Unmarshal([]byte(strings.TrimSpace(out)), &p) != nil {
		return windowsIdentityProbe{}, false
	}
	return p, true
}

// adminMembers returns the Administrators group's members. It is nil when
// neither Get-LocalGroupMember nor the ADSI fallback produced a list.
func (p windowsIdentityProbe) adminMembers() []shared.LocalAdminMember {
	rows := p.Admins
	if rows == nil {
		rows = p.AdminPaths
	}
	if rows == nil {
		return nil
	}
	members := []shared.LocalAdminMember{}
	for _, r := range rows {
		name := r.Name
		if name == "" {
			name = adsiPathName(r.Path)
		}
		if name == "" && r.SID == "" {
			continue
		}
		members = append(members, shared.LocalAdminMember{
			Name:           name,
			SID:            r.SID,
			Source:         windowsPrincipalSource(r.Source, r.SID, p.MachineSID),
			PrincipalClass: principalClass(r.Class),
		})
	}
	sortAdminMembers(members)
	return members
}

// adsiPathName turns an ADSI path into DOMAIN\name: "WinNT://CONTOSO/jdoe"
// gives "CONTOSO\jdoe", "WinNT://WORKGROUP/PC/alice" gives "PC\alice", and an
// unresolved "WinNT://S-1-12-1-…" gives the SID.
func adsiPathName(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "WinNT://"), "/")
	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}
	return strings.Join(parts, `\`)
}

// windowsPrincipalSource maps Get-LocalGroupMember's PrincipalSource to
// local/domain/entra, falling back to the SID: Entra principals have
// S-1-12-1-…, the machine's own accounts share its account-domain SID, and
// built-in groups (S-1-5-32-…) and well-known SIDs are local too.
func windowsPrincipalSource(source, sid, machineSID string) string {
	switch strings.ToLower(source) {
	case "local", "microsoftaccount":
		return "local"
	case "activedirectory":
		return "domain"
	case "azuread":
		return "entra"
	}
	switch {
	case strings.HasPrefix(sid, "S-1-12-1-"):
		return "entra"
	case machineSID != "" && strings.HasPrefix(sid, machineSID+"-"):
		return "local"
	case strings.HasPrefix(sid, "S-1-5-21-"):
		return "domain"
	default:
		return "local"
	}
}

func principalClass(class string) string {
	if strings.EqualFold(class, "group") {
		return "group"
	}
	return "user"
}

func sortAdminMembers(m []shared.LocalAdminMember) {
	sort.SliceStable(m, func(i, j int) bool { return strings.ToLower(m[i].Name) < strings.ToLower(m[j].Name) })
}

// consoleSession is the Win32_ComputerSystem.UserName fallback when the WTS
// session list can't be read: "DOMAIN\user" signed in at the console.
func (p windowsIdentityProbe) consoleSession() []shared.SignedInUser {
	if p.ConsoleUser == "" {
		return []shared.SignedInUser{}
	}
	domain, user, found := strings.Cut(p.ConsoleUser, `\`)
	if !found {
		domain, user = "", p.ConsoleUser
	}
	return []shared.SignedInUser{{Username: user, Domain: domain, Session: "console"}}
}

// parseDsregcmd reads `dsregcmd /status`: "AzureAdJoined : YES",
// "DomainJoined : YES", "DomainName : CONTOSO", "TenantId : …".
func parseDsregcmd(out string) (*shared.IdentityJoin, bool) {
	vals := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, " : ")
		if ok {
			vals[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	entra, entraOK := vals["AzureAdJoined"]
	domain, domainOK := vals["DomainJoined"]
	if !entraOK && !domainOK {
		return nil, false
	}
	j := &shared.IdentityJoin{Type: joinType(strings.EqualFold(domain, "YES"), strings.EqualFold(entra, "YES"))}
	if j.Type == "domain" || j.Type == "hybrid" {
		j.Domain = vals["DomainName"]
	}
	if j.Type == "entra" || j.Type == "hybrid" {
		j.TenantID = vals["TenantId"]
		j.TenantName = vals["TenantName"]
	}
	return j, true
}

// windowsJoinFallback uses Win32_ComputerSystem when dsregcmd isn't
// available; it can't see Entra join.
func (p windowsIdentityProbe) windowsJoinFallback() *shared.IdentityJoin {
	if p.PartOfDomain {
		return &shared.IdentityJoin{Type: "domain", Domain: p.Domain}
	}
	return &shared.IdentityJoin{Type: "workgroup"}
}

func joinType(domain, entra bool) string {
	switch {
	case domain && entra:
		return "hybrid"
	case domain:
		return "domain"
	case entra:
		return "entra"
	default:
		return "workgroup"
	}
}

// windowsLastUser normalises LogonUI's LastLoggedOnSAMUser/LastLoggedOnUser:
// ".\alice" is a local account, written "alice".
func windowsLastUser(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), `.\`)
}

// wtsSessionKind maps WTSClientProtocolType (0 console, 1 ICA, 2 RDP).
func wtsSessionKind(protocol uint16) string {
	switch protocol {
	case 0:
		return "console"
	case 2:
		return "rdp"
	default:
		return "ica"
	}
}

// ── macOS and Linux ──────────────────────────────────────────────────────────

var (
	whoISODate = regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$`)
	whoHost    = regexp.MustCompile(`\(([^)]*)\)\s*$`)
	whoTTYSeat = regexp.MustCompile(`^(tty\d+|seat\d+|:\d+)$`)
)

// parseWho parses `who`: "alice  console  Oct 22 09:01" on macOS, "bob
// pts/0  2026-10-22 10:15 (10.0.0.5)" on Linux. A session from a remote
// host is ssh; the console, a virtual terminal or an X display is console;
// any other line is a local terminal. Each user is listed once per kind of
// session, with its earliest sign-in. Times are local; now picks the year
// for macOS's yearless dates.
func parseWho(out string, now time.Time) []shared.SignedInUser {
	users := []shared.SignedInUser{}
	earliest := map[int]time.Time{} // index in users → earliest sign-in
	for _, line := range strings.Split(out, "\n") {
		u, t, ok := parseWhoLine(line, now)
		if !ok {
			continue
		}
		i := slices.IndexFunc(users, func(e shared.SignedInUser) bool {
			return e.Username == u.Username && e.Session == u.Session
		})
		if i < 0 {
			i = len(users)
			users = append(users, u)
		}
		if e, has := earliest[i]; !t.IsZero() && (!has || t.Before(e)) {
			earliest[i] = t
			users[i].Since = shared.ISOTime(t)
		}
	}
	return users
}

// parseWhoLine reads one `who` line; t is zero when its date can't be read.
func parseWhoLine(line string, now time.Time) (u shared.SignedInUser, t time.Time, ok bool) {
	f := strings.Fields(line)
	if len(f) < 3 {
		return u, t, false
	}
	host := ""
	if m := whoHost.FindStringSubmatch(line); m != nil {
		host = m[1]
	}
	u = shared.SignedInUser{Username: f[0], Session: whoSessionKind(f[1], host)}
	t, _ = whoTime(f[2:], now)
	return u, t, true
}

func whoSessionKind(line, host string) string {
	switch {
	case host != "" && !strings.HasPrefix(host, ":") && !whoTTYSeat.MatchString(host):
		return "ssh"
	case line == "console" || whoTTYSeat.MatchString(line) || whoTTYSeat.MatchString(host):
		return "console"
	default:
		return "terminal"
	}
}

// whoTime reads the date fields after the line name: "2026-10-22 10:15"
// (GNU) or "Oct 22 09:01" (BSD/macOS, no year).
func whoTime(f []string, now time.Time) (time.Time, bool) {
	if len(f) >= 2 && whoISODate.MatchString(f[0]+" "+f[1]) {
		t, err := time.ParseInLocation("2006-01-02 15:04", f[0]+" "+f[1], now.Location())
		return t, err == nil
	}
	if len(f) >= 3 {
		return yearlessTime("Jan _2 15:04", strings.Join(f[:3], " "), now)
	}
	return time.Time{}, false
}

// yearlessTime parses a date without a year as the latest such date not
// after now (allowing a minute of clock skew).
func yearlessTime(layout, value string, now time.Time) (time.Time, bool) {
	t, err := time.ParseInLocation(layout, value, now.Location())
	if err != nil {
		return time.Time{}, false
	}
	t = t.AddDate(now.Year()-t.Year(), 0, 0)
	if t.After(now.Add(time.Minute)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t, true
}

// addConsoleOwner adds the owner of /dev/console as a console session when
// `who` didn't list one (macOS); "root" means the login window is showing.
func addConsoleOwner(users []shared.SignedInUser, owner string) []shared.SignedInUser {
	owner = strings.TrimSpace(owner)
	if owner == "" || owner == "root" {
		return users
	}
	for _, u := range users {
		if u.Session == "console" {
			return users
		}
	}
	return append(users, shared.SignedInUser{Username: owner, Session: "console"})
}

// lastPseudoUsers are `last` entries that aren't sign-ins.
var lastPseudoUsers = map[string]bool{"reboot": true, "shutdown": true, "wtmp": true, "btmp": true}

// parseLastUser returns the user of the newest sign-in in `last` output.
func parseLastUser(out string) string {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || lastPseudoUsers[f[0]] || strings.HasPrefix(f[0], "wtmp") {
			continue
		}
		return f[0]
	}
	return ""
}

var lastDate = regexp.MustCompile(`\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) ((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d{1,2} \d{2}:\d{2})`)

// parseDarwinLastLogon reads `last -1 <user>` on macOS: "alice  console
// Wed Oct 22 09:01   still logged in". ok is false when there's no record
// (the log was rotated or the user never signed in; the two can't be told
// apart, so the key is left out).
func parseDarwinLastLogon(out, user string, now time.Time) (time.Time, bool) {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != user {
			continue
		}
		if m := lastDate.FindStringSubmatch(line); m != nil {
			return yearlessTime("Jan _2 15:04", strings.Join(strings.Fields(m[1]), " "), now)
		}
	}
	return time.Time{}, false
}

// parseDarwinGroupMembership reads `dscl . read /Groups/admin
// GroupMembership`: "GroupMembership: root alice".
func parseDarwinGroupMembership(out string) ([]string, bool) {
	_, rest, ok := strings.Cut(strings.TrimSpace(out), "GroupMembership:")
	if !ok {
		return nil, false
	}
	return strings.Fields(rest), true
}

// parseDsconfigad reads `dsconfigad -show`: "Active Directory Domain =
// corp.example.com" when bound. Empty output means not bound.
func parseDsconfigad(out string) *shared.IdentityJoin {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(k) == "Active Directory Domain" && strings.TrimSpace(v) != "" {
			return &shared.IdentityJoin{Type: "domain", Domain: strings.TrimSpace(v)}
		}
	}
	return &shared.IdentityJoin{Type: "workgroup"}
}

// parseRealmList reads `realm list`: each joined realm starts at column 0,
// followed by indented "key: value" lines. A realm counts once configured
// ("configured: kerberos-member").
func parseRealmList(out string) *shared.IdentityJoin {
	realm := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			realm = strings.TrimSpace(line)
			continue
		}
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && k == "configured" && strings.TrimSpace(v) != "no" && realm != "" {
			return &shared.IdentityJoin{Type: "domain", Domain: realm}
		}
	}
	return &shared.IdentityJoin{Type: "workgroup"}
}

// linuxAdminGroups are the groups whose members may use sudo by default.
var linuxAdminGroups = []string{"sudo", "wheel", "admin"}

// linuxAdminMembers lists the members of the admin groups in group-file
// lines ("sudo:x:27:alice,bob", from getent or /etc/group), plus accounts
// whose primary group is one of them. localUsers are the names in
// /etc/passwd; anyone else came from a directory service.
func linuxAdminMembers(groupLines string, primaryGID map[string]string, localUsers map[string]bool) []shared.LocalAdminMember {
	names := map[string]bool{}
	for _, line := range strings.Split(groupLines, "\n") {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) < 4 || !slices.Contains(linuxAdminGroups, f[0]) {
			continue
		}
		for _, m := range strings.Split(f[3], ",") {
			names[strings.TrimSpace(m)] = true
		}
		for user, gid := range primaryGID {
			names[user] = names[user] || gid == f[2]
		}
	}
	delete(names, "")
	members := []shared.LocalAdminMember{}
	for n, member := range names {
		if !member {
			continue
		}
		source := "domain"
		if localUsers[n] {
			source = "local"
		}
		members = append(members, shared.LocalAdminMember{Name: n, Source: source, PrincipalClass: "user"})
	}
	sortAdminMembers(members)
	return members
}

// parsePasswdGIDs maps every /etc/passwd account to its primary GID.
func parsePasswdGIDs(content string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), ":")
		if len(f) >= 4 && f[0] != "" && !strings.HasPrefix(f[0], "#") {
			out[f[0]] = f[3]
		}
	}
	return out
}

// darwinAdminMembers turns the admin group's members into entries; names
// in localUsers (dscl . list /Users) are local, the rest come from a
// directory (e.g. Active Directory) the Mac is bound to.
func darwinAdminMembers(names []string, localUsers map[string]bool) []shared.LocalAdminMember {
	members := []shared.LocalAdminMember{}
	for _, n := range names {
		source := "domain"
		if localUsers[n] {
			source = "local"
		}
		members = append(members, shared.LocalAdminMember{Name: n, Source: source, PrincipalClass: "user"})
	}
	sortAdminMembers(members)
	return members
}
