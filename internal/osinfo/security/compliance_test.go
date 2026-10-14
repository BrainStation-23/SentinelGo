package security

// Tests for the compliance telemetry parsers (#172). No OS suffix: every
// parser runs on every platform, so a Windows dev tests the Linux and macOS
// parsers too.

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

// js renders v as JSON, the form the server receives, so assertions check
// which keys are present and which are left out.
func js(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func assertJSON(t *testing.T, got any, want string) {
	t.Helper()
	if g := js(t, got); g != want {
		t.Errorf("got  %s\nwant %s", g, want)
	}
}

// ── shared helpers ────────────────────────────────────────────────────────────

func TestDecodeText(t *testing.T) {
	utf16le := []byte{0xFF, 0xFE, 'a', 0, '=', 0, '1', 0}
	utf16be := []byte{0xFE, 0xFF, 0, 'a', 0, '=', 0, '1'}
	cases := map[string][]byte{
		"utf16le": utf16le,
		"utf16be": utf16be,
		"utf8bom": append([]byte{0xEF, 0xBB, 0xBF}, "a=1"...),
		"plain":   []byte("a=1"),
	}
	for name, in := range cases {
		if got := decodeText(in); got != "a=1" {
			t.Errorf("%s: got %q", name, got)
		}
	}
}

func TestParseKeyValueConfAndINI(t *testing.T) {
	kv := parseKeyValueConf("# comment\nminlen = 12\nenforce_for_root\nDeny=5 # trailing\n")
	if kv["minlen"] != "12" || kv["deny"] != "5" {
		t.Errorf("parseKeyValueConf = %v", kv)
	}
	if _, ok := kv["enforce_for_root"]; !ok {
		t.Error("bare flag not kept")
	}
	ini := parseINI("top=1\n[Seat:*]\n; c\nautologin-user = bob\n[Daemon]\nX=Y\n")
	if ini[""]["top"] != "1" || ini["seat:*"]["autologin-user"] != "bob" || ini["daemon"]["x"] != "Y" {
		t.Errorf("parseINI = %v", ini)
	}
}

func TestNonZero(t *testing.T) {
	if nonZero(shared.RemoteAccessInfo{}) != nil {
		t.Error("empty struct should give nil")
	}
	if nonZero(shared.RemoteAccessInfo{SSHEnabled: shared.Bool(false)}) == nil {
		t.Error("a struct with a false value set is not empty")
	}
}

// ── Windows ───────────────────────────────────────────────────────────────────

const seceditSample = `[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = -1
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 10
NewGuestName = "Guest"
[Event Audit]
AuditLogonEvents = 3
[Version]
signature="$CHICAGO$"
`

func TestParseSeceditPasswordPolicy(t *testing.T) {
	assertJSON(t, parseSeceditPasswordPolicy(seceditSample),
		`{"min_length":14,"complexity":true,"max_age_days":0,"history":24,"lockout_threshold":10}`)

	defaults := strings.NewReplacer("= -1", "= 42", "= 14", "= 0", "Complexity = 1", "Complexity = 0", "= 24", "= 0", "= 10", "= 0").Replace(seceditSample)
	assertJSON(t, parseSeceditPasswordPolicy(defaults),
		`{"min_length":0,"complexity":false,"max_age_days":42,"history":0,"lockout_threshold":0}`)

	if p := parseSeceditPasswordPolicy("[Event Audit]\nMinimumPasswordLength = 9\n"); p != nil {
		t.Errorf("keys outside [System Access] must be ignored, got %+v", p)
	}
}

const auditpolSample = `Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
PC,System,Security State Change,{0CCE9210-69AE-11D9-BED3-505054503030},Success,,1
PC,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3
PC,System,File System,{0CCE921D-69AE-11D9-BED3-505054503030},No Auditing,,0
PC,System,User Account Management,{0cce9235-69ae-11d9-bed3-505054503030},Failure,,2
PC,System,Group Membership,{0CCE9249-69AE-11D9-BED3-505054503030},Success,,1
PC,,Option:CrashOnAuditFail,,Disabled,,0
`

func TestParseAuditpolBackup(t *testing.T) {
	enabled, cats, ok := parseAuditpolBackup(auditpolSample)
	if !ok || !enabled {
		t.Fatalf("enabled=%v ok=%v", enabled, ok)
	}
	want := []string{"Account Management", "Logon/Logoff", "System"}
	if !reflect.DeepEqual(cats, want) {
		t.Errorf("categories = %v, want %v", cats, want)
	}

	none := strings.NewReplacer(",,1", ",,0", ",,3", ",,0", ",,2", ",,0").Replace(auditpolSample)
	if enabled, cats, ok := parseAuditpolBackup(none); !ok || enabled || len(cats) != 0 {
		t.Errorf("all-off policy: enabled=%v cats=%v ok=%v", enabled, cats, ok)
	}
	if _, _, ok := parseAuditpolBackup("Machine Name,Policy Target\n"); ok {
		t.Error("no subcategory rows should give ok=false")
	}
}

func TestAuditCategoryOf(t *testing.T) {
	cases := map[string]string{
		"{0CCE9213-69AE-11D9-BED3-505054503030}": "System",
		"{0CCE9243-69AE-11D9-BED3-505054503030}": "Logon/Logoff",
		"{0CCE9245-69AE-11D9-BED3-505054503030}": "Object Access",
		"{0CCE9229-69AE-11D9-BED3-505054503030}": "Privilege Use",
		"{0CCE922B-69AE-11D9-BED3-505054503030}": "Detailed Tracking",
		"{0CCE9232-69AE-11D9-BED3-505054503030}": "Policy Change",
		"{0CCE923D-69AE-11D9-BED3-505054503030}": "DS Access",
		"{0CCE923F-69AE-11D9-BED3-505054503030}": "Account Logon",
		"{12345678-69AE-11D9-BED3-505054503030}": "",
		"not-a-guid":                             "",
	}
	for guid, want := range cases {
		if got := auditCategoryOf(guid); got != want {
			t.Errorf("auditCategoryOf(%s) = %q, want %q", guid, got, want)
		}
	}
}

func TestWindowsEventLogMB(t *testing.T) {
	if got := windowsEventLogMB(131072, 20971520); got == nil || *got != 128 {
		t.Errorf("policy KB should win: %v", got)
	}
	if got := windowsEventLogMB(-1, 20971520); got == nil || *got != 20 {
		t.Errorf("service bytes: %v", got)
	}
	if windowsEventLogMB(-1, -1) != nil {
		t.Error("nothing set should give nil")
	}
}

func TestWindowsScreenLock(t *testing.T) {
	locked := winSaverSettings{Active: true, Secure: true, TimeoutSeconds: 600}
	unlocked := winSaverSettings{Active: true, Secure: false, TimeoutSeconds: 300}
	cases := []struct {
		name    string
		machine int
		users   []winSaverSettings
		want    string
	}{
		{"nothing readable", -1, nil, "null"},
		{"machine policy only", 900, nil, `{"enabled":true,"idle_timeout_seconds":900,"require_password_on_wake":true}`},
		{"secure saver", -1, []winSaverSettings{locked}, `{"enabled":true,"idle_timeout_seconds":600,"require_password_on_wake":true}`},
		{"insecure saver", -1, []winSaverSettings{unlocked}, `{"enabled":false,"require_password_on_wake":false}`},
		{"no saver chosen", -1, []winSaverSettings{{}}, `{"enabled":false,"require_password_on_wake":false}`},
		{"machine policy shorter than saver", 300, []winSaverSettings{locked}, `{"enabled":true,"idle_timeout_seconds":300,"require_password_on_wake":true}`},
		{"machine policy covers insecure user", 900, []winSaverSettings{unlocked}, `{"enabled":true,"idle_timeout_seconds":900,"require_password_on_wake":true}`},
		{"weakest user wins", -1, []winSaverSettings{locked, unlocked}, `{"enabled":false,"require_password_on_wake":false}`},
		{"longest timeout of locked users", -1, []winSaverSettings{locked, {Active: true, Secure: true, TimeoutSeconds: 1200}}, `{"enabled":true,"idle_timeout_seconds":1200,"require_password_on_wake":true}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { assertJSON(t, windowsScreenLock(c.machine, c.users), c.want) })
	}
}

func TestWindowsRDP(t *testing.T) {
	cases := []struct {
		denyPol, deny, nlaPol, nla int
		want                       string
	}{
		{-1, 1, -1, 1, `{"rdp_enabled":false,"rdp_nla_required":true}`},
		{-1, 0, -1, 0, `{"rdp_enabled":true,"rdp_nla_required":false}`},
		{1, 0, 1, 0, `{"rdp_enabled":false,"rdp_nla_required":true}`}, // policy wins
		{-1, -1, -1, -1, `{}`},
	}
	for _, c := range cases {
		var r shared.RemoteAccessInfo
		r.RDPEnabled, r.RDPNLARequired = windowsRDP(c.denyPol, c.deny, c.nlaPol, c.nla)
		assertJSON(t, r, c.want)
	}
}

func TestWindowsAutoUpdate(t *testing.T) {
	cases := []struct {
		noAuto, auOpt, start int
		want                 string
	}{
		{-1, -1, 3, "true"},
		{1, -1, 3, "false"},
		{-1, 1, 3, "false"},
		{-1, 2, 3, "false"}, // notify before download
		{-1, 3, 3, "false"}, // download, notify before install
		{-1, 7, 3, "false"}, // notify to install and restart
		{-1, 4, 3, "true"},  // scheduled install
		{-1, 5, 3, "true"},  // local admin chooses
		{-1, -1, 4, "false"},
		{-1, -1, -1, "null"}, // wuauserv unreadable: unknown
		{1, -1, -1, "false"}, // policy off is enough
		{-1, 2, -1, "false"},
	}
	for _, c := range cases {
		b, _ := json.Marshal(windowsAutoUpdate(c.noAuto, c.auOpt, c.start))
		if string(b) != c.want {
			t.Errorf("windowsAutoUpdate(%d,%d,%d) = %s, want %s", c.noAuto, c.auOpt, c.start, b, c.want)
		}
	}
}

func TestWindowsBackupEnabled(t *testing.T) {
	for start, want := range map[int]string{2: "true", 0: "true", 3: "null", 4: "false", -1: "null"} {
		if b, _ := json.Marshal(windowsBackupEnabled(start)); string(b) != want {
			t.Errorf("windowsBackupEnabled(%d) = %s, want %s", start, b, want)
		}
	}
}

func TestWindowsTimeSync(t *testing.T) {
	assertJSON(t, windowsTimeSync("NTP", "time.windows.com,0x9 pool.ntp.org,0x1", 3), `{"enabled":true,"source":"time.windows.com"}`)
	assertJSON(t, windowsTimeSync("NT5DS", "", 2), `{"enabled":true,"source":"domain hierarchy"}`)
	assertJSON(t, windowsTimeSync("NoSync", "time.windows.com,0x9", 3), `{"enabled":false}`)
	assertJSON(t, windowsTimeSync("NTP", "x", 4), `{"enabled":false,"source":"x"}`)
	// Type unreadable: the service start type alone doesn't say it syncs.
	assertJSON(t, windowsTimeSync("", "", 3), `{}`)
	assertJSON(t, windowsTimeSync("", "", 4), `{"enabled":false}`)
	if windowsTimeSync("", "", -1) != nil {
		t.Error("nothing readable should give nil")
	}
}

func TestParseWinComplianceProbe(t *testing.T) {
	p, ok := parseWinComplianceProbe(`{"GuestEnabled":false,"LastUpdate":1760054040}`)
	if !ok || p.GuestEnabled == nil || *p.GuestEnabled || p.SMB1 != nil {
		t.Fatalf("probe = %+v ok=%v", p, ok)
	}
	if got := unixISOTime(p.LastUpdate); got != "2025-10-09T23:54:00Z" {
		t.Errorf("unixISOTime = %q", got)
	}
	if unixISOTime(nil) != "" {
		t.Error("nil time should be empty")
	}
	if _, ok := parseWinComplianceProbe(""); ok {
		t.Error("empty output should not parse")
	}
}

func TestParseWindowsMissingUpdates(t *testing.T) {
	out := `[{"Id":"KB5127648","Title":"2026-10 Security Update (KB5127648)","Critical":true},{"Id":"KB5000001","Title":"Feature update","Critical":false}]`
	updates, critical, ok := parseWindowsMissingUpdates(out)
	if !ok || critical != 1 || len(updates) != 2 || updates[0].ID != "KB5127648" {
		t.Fatalf("updates=%v critical=%d ok=%v", updates, critical, ok)
	}

	single := `{"Id":"KB1","Title":"t","Critical":true}`
	if u, c, ok := parseWindowsMissingUpdates(single); !ok || c != 1 || len(u) != 1 {
		t.Errorf("single object: %v %d %v", u, c, ok)
	}

	// "Checked, nothing missing" must stay distinct from "couldn't check".
	u, c, ok := parseWindowsMissingUpdates("[]")
	if !ok || c != 0 || u == nil || len(u) != 0 {
		t.Errorf("empty list: %v %d %v", u, c, ok)
	}
	assertJSON(t, shared.PatchingInfo{MissingUpdates: &u}, `{"missing_updates":[]}`)

	for _, bad := range []string{"", "Exception calling Search", "[not json"} {
		if _, _, ok := parseWindowsMissingUpdates(bad); ok {
			t.Errorf("%q should give ok=false", bad)
		}
	}
}

func TestParseWindowsMissingUpdates_Capped(t *testing.T) {
	rows := make([]string, maxMissingUpdates+5)
	for i := range rows {
		rows[i] = `{"Id":"KB1","Title":"t","Critical":true}`
	}
	updates, critical, ok := parseWindowsMissingUpdates("[" + strings.Join(rows, ",") + "]")
	if !ok || len(updates) != maxMissingUpdates || critical != maxMissingUpdates+5 {
		t.Errorf("len=%d critical=%d ok=%v", len(updates), critical, ok)
	}
}

// ── Linux: password policy ────────────────────────────────────────────────────

const debianCommonPassword = `# /etc/pam.d/common-password
password	requisite			pam_pwquality.so retry=3 minlen=12 dcredit=-1 ucredit=-1 lcredit=-1
password	[success=1 default=ignore]	pam_unix.so obscure use_authtok try_first_pass yescrypt remember=5
password	requisite			pam_deny.so
`

const rhelSystemAuth = `auth        required      pam_env.so
auth        required      pam_faillock.so preauth silent deny=5
auth        sufficient    pam_unix.so
-auth       sufficient    pam_sss.so
password    requisite     pam_pwquality.so local_users_only
password    required      pam_pwhistory.so use_authtok
password    sufficient    pam_unix.so yescrypt shadow use_authtok
`

func TestLinuxPasswordPolicy(t *testing.T) {
	cases := []struct {
		name string
		src  linuxPasswordSources
		want string
	}{
		{
			"debian pwquality with credits",
			linuxPasswordSources{LoginDefs: "PASS_MAX_DAYS\t99999\nPASS_MIN_LEN 5\n", PAM: debianCommonPassword, PAMRead: true},
			`{"min_length":12,"complexity":true,"max_age_days":0,"history":5,"lockout_threshold":0}`,
		},
		{
			"rhel pwquality.conf, faillock, pwhistory",
			linuxPasswordSources{
				LoginDefs: "PASS_MAX_DAYS 90\n", PwQuality: "minlen = 14\nminclass = 4\n",
				PwHistory: "remember = 24\n", PAM: rhelSystemAuth, PAMRead: true,
			},
			`{"min_length":14,"complexity":true,"max_age_days":90,"history":24,"lockout_threshold":5}`,
		},
		{
			"faillock.conf deny and module defaults",
			linuxPasswordSources{
				Faillock: "deny = 7\n",
				PAM:      "auth required pam_faillock.so preauth\npassword required pam_pwhistory.so\npassword sufficient pam_unix.so\n",
				PAMRead:  true,
			},
			`{"min_length":6,"complexity":false,"history":10,"lockout_threshold":7}`,
		},
		{
			"pwquality.conf ignored for cracklib",
			linuxPasswordSources{PwQuality: "minlen = 20\n", PAM: "password requisite pam_cracklib.so minclass=2\n", PAMRead: true},
			`{"complexity":false,"history":0,"lockout_threshold":0}`,
		},
		{
			"no PAM readable: only login.defs",
			linuxPasswordSources{LoginDefs: "PASS_MIN_LEN 8\nPASS_MAX_DAYS 60\n"},
			`{"min_length":8,"max_age_days":60}`,
		},
		{"nothing readable", linuxPasswordSources{}, "null"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { assertJSON(t, linuxPasswordPolicy(c.src), c.want) })
	}
}

func TestParsePAMLine(t *testing.T) {
	e, ok := parsePAMLine("-password [success=1 default=ignore] /lib/security/pam_unix.so obscure minlen=8 # comment")
	if !ok || e.kind != "password" || e.module != "pam_unix.so" || e.args["minlen"] != "8" {
		t.Errorf("entry = %+v ok=%v", e, ok)
	}
	if _, ok := e.args["obscure"]; !ok {
		t.Error("flag argument missing")
	}
	for _, skip := range []string{"@include common-password", "# password required pam_unix.so", "auth required", "auth [default=die"} {
		if _, ok := parsePAMLine(skip); ok {
			t.Errorf("%q should be skipped", skip)
		}
	}
}

// ── Linux: screen lock, login, units ──────────────────────────────────────────

func TestGnomeScreenLock(t *testing.T) {
	cases := []struct {
		name                               string
		lockEnabled, disabled, idle, delay string
		want                               string
	}{
		{"locks after idle plus delay", "true", "false", "uint32 300", "uint32 30", `{"enabled":true,"idle_timeout_seconds":330,"require_password_on_wake":true}`},
		{"idle never", "true", "false", "uint32 0", "uint32 0", `{"enabled":false,"require_password_on_wake":true}`},
		{"lock off", "false", "false", "uint32 300", "uint32 0", `{"enabled":false,"require_password_on_wake":false}`},
		{"lockdown disables the lock screen", "true", "true", "uint32 300", "uint32 0", `{"enabled":false,"require_password_on_wake":false}`},
		{"idle unreadable", "true", "", "", "", `{"require_password_on_wake":true}`},
		{"lock-delay unreadable", "true", "false", "uint32 300", "", `{"enabled":true,"require_password_on_wake":true}`},
		{"not GNOME", "", "", "uint32 300", "", "null"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertJSON(t, gnomeScreenLock(c.lockEnabled, c.disabled, c.idle, c.delay), c.want)
		})
	}
}

func TestLoginctlParsing(t *testing.T) {
	s := parseLoginctlSessions("     2 1000 alice seat0 tty2\n    c1  120 gdm   seat0 tty1\n")
	if len(s) != 2 || s[0] != (loginSession{ID: "2", UID: "1000", User: "alice"}) {
		t.Errorf("sessions = %+v", s)
	}
	if !isActiveGraphicalSession("Type=wayland\nActive=yes\n") || !isActiveGraphicalSession("Type=x11\nActive=yes") {
		t.Error("graphical active session not detected")
	}
	if isActiveGraphicalSession("Type=tty\nActive=yes") || isActiveGraphicalSession("Type=x11\nActive=no") {
		t.Error("tty or inactive session must not count")
	}
}

func TestLinuxAutoLoginParsers(t *testing.T) {
	if !gdmAutoLogin("[daemon]\nAutomaticLoginEnable=True\nAutomaticLogin=bob\n") || !gdmAutoLogin("[daemon]\nTimedLoginEnable=true\n") {
		t.Error("GDM autologin not detected")
	}
	if gdmAutoLogin("[daemon]\n#AutomaticLoginEnable=True\n[security]\nAutomaticLoginEnable=true\n") {
		t.Error("commented or wrong-section GDM setting must not count")
	}
	if auto, guest := lightdmLogin("[Seat:*]\nautologin-user=bob\nallow-guest=true\n"); !auto || !guest {
		t.Errorf("lightdm auto=%v guest=%v", auto, guest)
	}
	if auto, guest := lightdmLogin("[Seat:*]\nautologin-user=\nallow-guest=false\n"); auto || guest {
		t.Errorf("empty lightdm settings: auto=%v guest=%v", auto, guest)
	}
	if !sddmAutoLogin("[Autologin]\nUser=bob\nSession=plasma\n") || sddmAutoLogin("[Autologin]\nUser=\n") {
		t.Error("SDDM autologin detection wrong")
	}
	if !gettyAutoLogin("[Service]\nExecStart=\nExecStart=-/sbin/agetty --autologin bob --noclear %I $TERM\n") {
		t.Error("getty --autologin not detected")
	}
	if !gettyAutoLogin("[Service]\nExecStart=-/sbin/agetty -a root --noclear %I\n") {
		t.Error("getty -a not detected")
	}
	if gettyAutoLogin("[Service]\nExecStart=-/sbin/agetty --noclear %I $TERM\n") {
		t.Error("plain getty flagged as autologin")
	}
}

func TestLinuxRemoteAccess(t *testing.T) {
	active := parseUnitList(`ssh.socket loaded active listening OpenBSD Secure Shell server socket
smbd.service loaded active running Samba SMB Daemon
cron.service loaded active running Regular background program processing daemon
`)
	assertJSON(t, linuxRemoteAccess(active, "[global]\n   server min protocol = NT1\n"),
		`{"rdp_enabled":false,"smb1_enabled":true,"ssh_enabled":true,"screen_sharing_enabled":false}`)
	assertJSON(t, linuxRemoteAccess(active, "[global]\nworkgroup = X\n"),
		`{"rdp_enabled":false,"smb1_enabled":false,"ssh_enabled":true,"screen_sharing_enabled":false}`)

	desktop := parseUnitList("xrdp.service loaded active running xrdp\nx11vnc.service loaded active running VNC\n")
	assertJSON(t, linuxRemoteAccess(desktop, "[global]\nserver min protocol = NT1\n"),
		`{"rdp_enabled":true,"smb1_enabled":false,"ssh_enabled":false,"screen_sharing_enabled":true}`)
}

func TestParseUnitList(t *testing.T) {
	units := parseUnitList("● foo.service loaded failed failed Foo\nbar.timer enabled enabled\n\n")
	if units["foo.service"] != "loaded" || units["bar.timer"] != "enabled" || len(units) != 2 {
		t.Errorf("units = %v", units)
	}
}

// ── Linux: patching ───────────────────────────────────────────────────────────

func TestLastDpkgUpgrade(t *testing.T) {
	log := `2026-10-10 03:00:00 startup archives unpack
2026-10-10 03:00:01 upgrade openssl:amd64 3.0.1 3.0.2
2026-10-12 04:00:00 install newpkg:amd64 <none> 1.0
2026-10-11 05:30:00 upgrade bash:amd64 5.1 5.2
2026-10-11 05:30:01 status installed bash:amd64 5.2
`
	got, ok := lastDpkgUpgrade(log, time.UTC)
	if !ok || shared.ISOTime(got) != "2026-10-11T05:30:00Z" {
		t.Errorf("got %v ok=%v (installs must not count, only upgrades)", got, ok)
	}
	if _, ok := lastDpkgUpgrade("2026-10-12 04:00:00 install x 1\n", time.UTC); ok {
		t.Error("log without upgrades should give ok=false")
	}
}

func TestLastDnfUpgrade(t *testing.T) {
	log := `2026-10-10T03:00:00+0000 INFO --- logging initialized ---
2026-10-11T05:30:00+0000 SUBDEBUG Upgrade: bash-5.2.26-3.el9.x86_64
2026-10-11T05:30:01+0000 SUBDEBUG Upgraded: bash-5.2.26-1.el9.x86_64
2026-10-13T09:00:00+0000 SUBDEBUG Installed: newapp-1.0-1.el9.x86_64
2026-10-09T01:00:00Z SUBDEBUG Upgrade: openssl-3.0.7-28.el9.x86_64
`
	got, ok := lastDnfUpgrade(log)
	if !ok || shared.ISOTime(got) != "2026-10-11T05:30:00Z" {
		t.Errorf("got %v ok=%v (a new install must not count as an update)", got, ok)
	}
	if _, ok := lastDnfUpgrade("2026-10-13T09:00:00+0000 SUBDEBUG Installed: newapp-1.0\n"); ok {
		t.Error("installs only should give ok=false")
	}
}

func TestLastPacmanUpgrade(t *testing.T) {
	log := `[2026-10-10T03:00:00+0000] [ALPM] upgraded linux (6.1-1 -> 6.2-1)
[2026-10-12T04:00:00+0200] [ALPM] installed foo (1.0-1)
[2026-10-11T05:30:00+0000] [ALPM] upgraded bash (5.1 -> 5.2)
[2019-10-12 04:00] [ALPM] upgraded old (1 -> 2)
`
	got, ok := lastPacmanUpgrade(log, time.UTC)
	if !ok || shared.ISOTime(got) != "2026-10-11T05:30:00Z" {
		t.Errorf("got %v ok=%v", got, ok)
	}
}

func TestNeedrestartKernelPending(t *testing.T) {
	cases := map[string][3]bool{ // pending, ok
		"NEEDRESTART-VER: 3.6\nNEEDRESTART-KCUR: 6.1\nNEEDRESTART-KSTA: 1\n": {false, true},
		"NEEDRESTART-KSTA: 3\n": {true, true},
		"NEEDRESTART-KSTA: 0\n": {false, false},
		"":                      {false, false},
	}
	for out, want := range cases {
		pending, ok := needrestartKernelPending(out)
		if pending != want[0] || ok != want[1] {
			t.Errorf("%q: pending=%v ok=%v", out, pending, ok)
		}
	}
}

func TestAptUnattendedEnabled(t *testing.T) {
	on := `APT::Periodic::Update-Package-Lists "1";` + "\n" + `APT::Periodic::Unattended-Upgrade "1";`
	if !aptUnattendedEnabled(on) {
		t.Error("enabled config not detected")
	}
	if aptUnattendedEnabled(on + "\n" + `APT::Periodic::Unattended-Upgrade "0";`) {
		t.Error("a later file turning it off must win")
	}
	if aptUnattendedEnabled(`APT::Periodic::Update-Package-Lists "1";`) {
		t.Error("unset must count as off")
	}
	commented := []string{
		`// APT::Periodic::Unattended-Upgrade "1";`,
		`# APT::Periodic::Unattended-Upgrade "1";`,
		"/* APT::Periodic::Unattended-Upgrade \"1\";\n */",
		`APT::Periodic::Unattended-Upgrade "0";` + "\n" + `// APT::Periodic::Unattended-Upgrade "1";`,
	}
	for _, c := range commented {
		if aptUnattendedEnabled(c) {
			t.Errorf("commented-out setting counted: %q", c)
		}
	}
	if !aptUnattendedEnabled(`APT::Periodic::Unattended-Upgrade "1"; // keep on`) {
		t.Error("a trailing comment must not hide the setting")
	}
}

func TestDnfAutomaticApplies(t *testing.T) {
	if !dnfAutomaticApplies("[commands]\nupgrade_type = security\napply_updates = yes\n") {
		t.Error("apply_updates=yes not detected")
	}
	if dnfAutomaticApplies("[commands]\napply_updates = no\n") || dnfAutomaticApplies("[emitters]\napply_updates = yes\n") {
		t.Error("apply_updates off or in wrong section must not count")
	}
}

// ── Linux: audit, time, backup ────────────────────────────────────────────────

func TestParseAuditRules(t *testing.T) {
	rules, keys := parseAuditRules(`-w /etc/passwd -p wa -k identity
-a always,exit -F arch=b64 -S execve -F key=exec
-w /etc/shadow -p wa -k identity
-a always,exit -F arch=b64 -S mount -F key=(null)
`)
	if rules != 4 || !reflect.DeepEqual(keys, []string{"exec", "identity"}) {
		t.Errorf("rules=%d keys=%v", rules, keys)
	}
	if rules, keys := parseAuditRules("No rules\n"); rules != 0 || keys != nil {
		t.Errorf("no rules: %d %v", rules, keys)
	}
}

func TestTimeSyncParsers(t *testing.T) {
	if on, ok := timedatectlNTP("NTP=yes\n"); !on || !ok {
		t.Error("NTP=yes")
	}
	if on, ok := timedatectlNTP("NTP=no"); on || !ok {
		t.Error("NTP=no")
	}
	if _, ok := timedatectlNTP(""); ok {
		t.Error("empty output")
	}

	src, off := parseChronyTracking("A9FEA97B,169.254.169.123,4,1760054040.123,-0.003141,0.000012,0.000020,-12.5,0.01,0.1,0.001,0.002,64.0,Normal\n")
	if src != "169.254.169.123" || off == nil || *off != -3 {
		t.Errorf("chrony: %q %v", src, off)
	}

	src, off = parseTimesyncStatus(`       Server: 185.125.190.56 (ntp.ubuntu.com)
Poll interval: 34min 8s (min: 32s; max 34min 8s)
         Leap: normal
       Offset: -1.678ms
`)
	if src != "ntp.ubuntu.com" || off == nil || *off != -2 {
		t.Errorf("timesyncd: %q %v", src, off)
	}

	src, off = parseNtpqPeers(`     remote           refid      st t when poll reach   delay   offset  jitter
==============================================================================
+10.0.0.1        .GPS.            1 u   20   64  377    0.512    0.101   0.020
*10.0.0.2        .PPS.            1 u   18   64  377    0.430   12.402   0.031
`)
	if src != "10.0.0.2" || off == nil || *off != 12 {
		t.Errorf("ntpq: %q %v", src, off)
	}
}

func TestParseSystemdTimespan(t *testing.T) {
	cases := map[string]int64{"-1.678ms": -2, "512us": 1, "+1.5s": 1500, "2min": 120000, "999µs": 1}
	for in, want := range cases {
		if got := parseSystemdTimespan(in); got == nil || *got != want {
			t.Errorf("%q = %v, want %d", in, got, want)
		}
	}
	if parseSystemdTimespan("n/a") != nil {
		t.Error("garbage should give nil")
	}
}

func TestLinuxBackup(t *testing.T) {
	units := parseUnitList("borgmatic.timer enabled enabled\nborgmatic.service static -\nrestic-backup.timer disabled enabled\n")
	assertJSON(t, linuxBackup(units), `{"product":"borgmatic","enabled":true}`)
	assertJSON(t, linuxBackup(parseUnitList("restic-backup.timer disabled enabled\n")), `{"product":"restic","enabled":false}`)
	if linuxBackup(parseUnitList("cron.service enabled enabled\n")) != nil {
		t.Error("no backup units should give nil")
	}
}

// ── macOS ─────────────────────────────────────────────────────────────────────

const pwpolicySample = `Getting global account policies
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>policyCategoryAuthentication</key>
	<array>
		<dict>
			<key>policyContent</key>
			<string>(policyAttributeFailedAuthentications &lt; policyAttributeMaximumFailedAuthentications)</string>
			<key>policyIdentifier</key>
			<string>com.apple.maximumFailedLoginAttempts</string>
			<key>policyParameters</key>
			<dict>
				<key>policyAttributeMaximumFailedAuthentications</key>
				<integer>10</integer>
			</dict>
		</dict>
	</array>
	<key>policyCategoryPasswordChange</key>
	<array>
		<dict>
			<key>policyContent</key>
			<string>policyAttributeCurrentTime &gt; policyAttributeLastPasswordChangeTime + (policyAttributeExpiresEveryNDays * 24 * 60 * 60)</string>
			<key>policyParameters</key>
			<dict>
				<key>policyAttributeExpiresEveryNDays</key>
				<integer>90</integer>
			</dict>
		</dict>
	</array>
	<key>policyCategoryPasswordContent</key>
	<array>
		<dict>
			<key>policyContent</key>
			<string>policyAttributePassword matches '.{12,}+'</string>
			<key>policyIdentifier</key>
			<string>com.apple.policy.legacy.minChars</string>
			<key>policyParameters</key>
			<dict>
				<key>minimumLength</key>
				<integer>12</integer>
			</dict>
		</dict>
		<dict>
			<key>policyContent</key>
			<string>policyAttributePassword matches '(.*[0-9].*){1,}+'</string>
			<key>policyIdentifier</key>
			<string>com.apple.policy.legacy.requiresNumeric</string>
		</dict>
		<dict>
			<key>policyContent</key>
			<string>policyAttributePassword matches '(.*[a-zA-Z].*){1,}+'</string>
			<key>policyIdentifier</key>
			<string>com.apple.policy.legacy.requiresAlpha</string>
		</dict>
		<dict>
			<key>policyContent</key>
			<string>none policyAttributePasswordHashes in policyAttributePasswordHistory</string>
			<key>policyParameters</key>
			<dict>
				<key>policyAttributePasswordHistoryDepth</key>
				<integer>5</integer>
			</dict>
		</dict>
	</array>
</dict>
</plist>
`

func TestMacPasswordPolicy(t *testing.T) {
	assertJSON(t, macPasswordPolicy(pwpolicySample),
		`{"min_length":12,"complexity":true,"max_age_days":90,"history":5,"lockout_threshold":10}`)

	zero := `{"min_length":0,"complexity":false,"max_age_days":0,"history":0,"lockout_threshold":0}`
	assertJSON(t, macPasswordPolicy("Getting global account policies\nNo global policies are set.\n"), zero)
	assertJSON(t, macPasswordPolicy(`<?xml version="1.0"?><plist version="1.0"><dict/></plist>`), zero)

	lengthOnlyByRegex := strings.Replace(pwpolicySample, "<key>minimumLength</key>\n\t\t\t\t<integer>12</integer>", "", 1)
	if p := macPasswordPolicy(lengthOnlyByRegex); p == nil || p.MinLength == nil || *p.MinLength != 12 {
		t.Errorf("min length from the policyContent regex: %s", js(t, p))
	}

	if macPasswordPolicy("pwpolicy: command failed") != nil {
		t.Error("unrecognised output should give nil")
	}
}

// Policies in several categories all apply, so the strictest value must win
// whatever order the (unordered) category map is walked in.
func TestMacPasswordPolicy_StrictestWins(t *testing.T) {
	entry := func(params string) string {
		return `<dict><key>policyContent</key><string>x</string><key>policyParameters</key><dict>` + params + `</dict></dict>`
	}
	out := `<?xml version="1.0"?><plist version="1.0"><dict>` +
		`<key>policyCategoryA</key><array>` +
		entry(`<key>minimumLength</key><integer>8</integer><key>policyAttributeExpiresEveryNDays</key><integer>90</integer>`) +
		entry(`<key>policyAttributeMaximumFailedAuthentications</key><integer>10</integer><key>policyAttributePasswordHistoryDepth</key><integer>3</integer>`) +
		`</array><key>policyCategoryB</key><array>` +
		entry(`<key>minimumLength</key><integer>14</integer><key>maxMinutesUntilChangePassword</key><integer>86400</integer>`) +
		entry(`<key>maxFailedAttempts</key><integer>5</integer><key>policyAttributePasswordHistoryDepth</key><integer>12</integer>`) +
		`</array></dict></plist>`
	want := `{"min_length":14,"complexity":false,"max_age_days":60,"history":12,"lockout_threshold":5}`
	for i := 0; i < 20; i++ { // map order varies between runs
		assertJSON(t, macPasswordPolicy(out), want)
	}
}

func TestMinPositive(t *testing.T) {
	cases := [][3]int{{0, 0, 0}, {0, 5, 5}, {5, 0, 5}, {5, 3, 3}, {3, 5, 3}, {-1, 4, 4}}
	for _, c := range cases {
		if got := minPositive(c[0], c[1]); got != c[2] {
			t.Errorf("minPositive(%d,%d) = %d, want %d", c[0], c[1], got, c[2])
		}
	}
}

func TestParseSysadminctlScreenLock(t *testing.T) {
	cases := []struct {
		out      string
		required bool
		delay    int
		ok       bool
	}{
		{"2026-10-14 10:00:00.123 sysadminctl[123:456] screenLock delay is immediate", true, 0, true},
		{"2026-10-14 10:00:00.123 sysadminctl[123:456] screenLock delay is 5 seconds", true, 5, true},
		{"2026-10-14 10:00:00.123 sysadminctl[123:456] screenLock is off", false, 0, true},
		{"sysadminctl: unrecognized", false, 0, false},
	}
	for _, c := range cases {
		required, delay, ok := parseSysadminctlScreenLock(c.out)
		if required != c.required || delay != c.delay || ok != c.ok {
			t.Errorf("%q: %v %d %v", c.out, required, delay, ok)
		}
	}
}

func TestParsePmsetDisplaySleep(t *testing.T) {
	out := "System-wide power settings:\nCurrently in use:\n standby              1\n displaysleep         10 (sleep prevented by coreaudiod)\n sleep                1\n"
	if n, ok := parsePmsetDisplaySleep(out); !ok || n != 10 {
		t.Errorf("displaysleep = %d ok=%v", n, ok)
	}
	if _, ok := parsePmsetDisplaySleep("sleep 1\n"); ok {
		t.Error("missing displaysleep should give ok=false")
	}
}

func TestMacScreenLock(t *testing.T) {
	yes, no := shared.Bool(true), shared.Bool(false)
	cases := []struct {
		name                string
		saver, displaySleep int
		password            *bool
		delay               int
		want                string
	}{
		{"display sleeps first", 1200, 10, yes, 0, `{"enabled":true,"idle_timeout_seconds":600,"require_password_on_wake":true}`},
		{"saver first plus delay", 300, 0, yes, 5, `{"enabled":true,"idle_timeout_seconds":305,"require_password_on_wake":true}`},
		{"password off", 300, 10, no, 0, `{"enabled":false,"require_password_on_wake":false}`},
		{"never idle", 0, 0, yes, 0, `{"enabled":false,"require_password_on_wake":true}`},
		{"password unknown", 300, 10, nil, 0, `{"idle_timeout_seconds":300}`},
		// The unread display sleep could lock sooner: no timeout.
		{"display sleep unknown", 300, -1, yes, 0, `{"enabled":true,"require_password_on_wake":true}`},
		{"idle unknown", -1, -1, yes, 0, `{"require_password_on_wake":true}`},
		{"nothing known", -1, -1, nil, 0, "null"},
		// One idle source off and the other unread could still lock: don't claim off.
		{"display never, saver unread", -1, 0, yes, 0, `{"require_password_on_wake":true}`},
		{"saver never, display unread", 0, -1, yes, 0, `{"require_password_on_wake":true}`},
		{"delay unknown", 300, 0, yes, -1, `{"enabled":true,"require_password_on_wake":true}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertJSON(t, macScreenLock(c.saver, c.displaySleep, c.password, c.delay), c.want)
		})
	}
}

func TestMacLastUpdate(t *testing.T) {
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><array>
<dict><key>date</key><date>2026-10-02T18:30:00Z</date><key>displayName</key><string>macOS Sequoia 15.7.1</string><key>processName</key><string>softwareupdated</string></dict>
<dict><key>date</key><date>2026-10-12T09:00:00Z</date><key>displayName</key><string>XProtectPlistConfigData</string><key>processName</key><string>softwareupdated</string></dict>
<dict><key>date</key><date>2026-10-13T09:00:00Z</date><key>displayName</key><string>Slack</string><key>processName</key><string>appstoreagent</string></dict>
<dict><key>date</key><date>2026-09-01T10:00:00Z</date><key>displayName</key><string>Security Update</string><key>processName</key><string>Software Update</string></dict>
</array></plist>`
	root, err := shared.DecodePlistXML([]byte(plist))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := macLastUpdate(root)
	if !ok || shared.ISOTime(got) != "2026-10-02T18:30:00Z" {
		t.Errorf("got %v ok=%v (background data files and App Store installs must not count)", got, ok)
	}
	if _, ok := macLastUpdate(nil); ok {
		t.Error("nil root should give ok=false")
	}
}

func TestMacAutoUpdate(t *testing.T) {
	all := map[string]any{"AutomaticallyInstallMacOSUpdates": true}
	if !macAutoUpdate(all) {
		t.Error("macOS installs on, other keys at their default (on): automatic")
	}
	if macAutoUpdate(map[string]any{}) {
		t.Error("installing macOS updates defaults to off")
	}
	if macAutoUpdate(map[string]any{"AutomaticCheckEnabled": true, "CriticalUpdateInstall": true}) {
		t.Error("checks and security responses alone don't install OS updates")
	}
	off := []map[string]any{
		{"AutomaticallyInstallMacOSUpdates": true, "CriticalUpdateInstall": false},
		{"AutomaticallyInstallMacOSUpdates": int64(1), "AutomaticCheckEnabled": int64(0)},
	}
	for _, p := range off {
		if macAutoUpdate(p) {
			t.Errorf("%v must count as off", p)
		}
	}
}

func TestMacAuditTimeBackupParsers(t *testing.T) {
	flags, ok := parseAuditControl("#\ndir:/var/audit\nflags:lo,aa, ad\nminfree:5\n")
	if !ok || !reflect.DeepEqual(flags, []string{"lo", "aa", "ad"}) {
		t.Errorf("flags=%v ok=%v", flags, ok)
	}
	if _, ok := parseAuditControl("dir:/var/audit\n"); ok {
		t.Error("no flags line should give ok=false")
	}

	if colonValue("Network Time: On\n") != "On" || colonValue("Network Time Server: time.apple.com") != "time.apple.com" {
		t.Error("colonValue")
	}

	got, ok := parseTimeMachineLatest("/Volumes/.timemachine/ABC/2026-10-14-010000.backup/2026-10-14-010000.backup\n", time.UTC)
	if !ok || shared.ISOTime(got) != "2026-10-14T01:00:00Z" {
		t.Errorf("latest backup %v ok=%v", got, ok)
	}
	if _, ok := parseTimeMachineLatest("Failed to mount backup destination", time.UTC); ok {
		t.Error("error output should give ok=false")
	}

	if !tmHasDestination("====================================================\nName          : Backup\nKind          : Network\n") {
		t.Error("destination not detected")
	}
	if tmHasDestination("No destinations configured.\n") {
		t.Error("no destination flagged as configured")
	}
}
