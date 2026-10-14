package security

// Linux compliance parsers. No OS suffix so they are tested everywhere;
// compliance_linux.go calls them.

import (
	"bufio"
	"math"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

// ── password policy ───────────────────────────────────────────────────────────

// pamEntry is one module line of a PAM stack, e.g.
// "password [success=1 default=ignore] pam_unix.so obscure yescrypt".
type pamEntry struct {
	kind   string            // password, auth, account, session
	module string            // basename, e.g. pam_unix.so
	args   map[string]string // "minlen=12" -> minlen:12; flags map to ""
}

// parsePAM parses PAM stack files. Comments, @include lines and malformed
// lines are skipped; a leading "-" (load if present) is dropped.
func parsePAM(content string) []pamEntry {
	var out []pamEntry
	for _, line := range strings.Split(content, "\n") {
		if e, ok := parsePAMLine(line); ok {
			out = append(out, e)
		}
	}
	return out
}

func parsePAMLine(line string) (pamEntry, bool) {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	f := strings.Fields(line)
	if len(f) < 3 || strings.HasPrefix(f[0], "@") {
		return pamEntry{}, false
	}
	i := 1
	if strings.HasPrefix(f[i], "[") { // control may contain spaces: [success=1 default=ignore]
		for i < len(f) && !strings.HasSuffix(f[i], "]") {
			i++
		}
	}
	i++
	if i >= len(f) {
		return pamEntry{}, false
	}
	e := pamEntry{
		kind:   strings.ToLower(strings.TrimPrefix(f[0], "-")),
		module: path.Base(f[i]),
		args:   map[string]string{},
	}
	for _, a := range f[i+1:] {
		k, v, _ := strings.Cut(a, "=")
		e.args[strings.ToLower(k)] = v
	}
	return e, true
}

// findPAM returns the first entry of the given kind for one of modules.
func findPAM(entries []pamEntry, kind string, modules ...string) (pamEntry, bool) {
	for _, e := range entries {
		if e.kind != kind {
			continue
		}
		for _, m := range modules {
			if e.module == m {
				return e, true
			}
		}
	}
	return pamEntry{}, false
}

// linuxPasswordSources is what linuxPasswordPolicy reads. Missing files are
// "". PAMRead is false when no PAM stack file could be read, in which case
// the PAM-derived fields are left out instead of reported as "none".
type linuxPasswordSources struct {
	LoginDefs string // /etc/login.defs
	PwQuality string // /etc/security/pwquality.conf (+ .d/*.conf)
	Faillock  string // /etc/security/faillock.conf
	PwHistory string // /etc/security/pwhistory.conf
	PAM       string // common-password + common-auth, or system-auth + password-auth
	PAMRead   bool
}

// argOr returns the module argument, else the config file value, as an int.
func argOr(e pamEntry, conf map[string]string, key string) (int, bool) {
	v, ok := e.args[key]
	if !ok {
		v, ok = conf[key]
	}
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	return n, err == nil
}

// linuxPasswordPolicy derives the policy PAM enforces:
//   - min_length: pam_pwquality/pam_cracklib minlen, else pam_unix minlen
//     (default 6), else PASS_MIN_LEN from login.defs.
//   - complexity: pam_pwquality/pam_cracklib requiring at least 3 character
//     classes (minclass >= 3, or 3+ negative *credit settings).
//   - max_age_days: PASS_MAX_DAYS (99999 = never = 0). It applies to accounts
//     created afterwards; existing accounts keep their own shadow setting.
//   - history: pam_pwhistory remember (default 10), else pam_unix remember.
//   - lockout_threshold: pam_faillock deny (default 3), else pam_tally2 deny.
func linuxPasswordPolicy(src linuxPasswordSources) *shared.PasswordPolicyInfo {
	defs := parseLoginDefs(src.LoginDefs)
	pam := parsePAM(src.PAM)
	quality := parseKeyValueConf(src.PwQuality)
	var p shared.PasswordPolicyInfo

	qmod, hasQuality := findPAM(pam, "password", "pam_pwquality.so", "pam_cracklib.so")
	unix, hasUnix := findPAM(pam, "password", "pam_unix.so")
	switch {
	case hasQuality:
		if n, ok := argOr(qmod, qualityConf(qmod, quality), "minlen"); ok {
			p.MinLength = shared.Int(n)
		}
	case hasUnix:
		n, ok := argOr(unix, nil, "minlen")
		if !ok {
			n = 6
		}
		p.MinLength = shared.Int(n)
	}
	if p.MinLength == nil {
		if n, err := strconv.Atoi(defs["PASS_MIN_LEN"]); err == nil {
			p.MinLength = shared.Int(n)
		}
	}

	if n, err := strconv.Atoi(defs["PASS_MAX_DAYS"]); err == nil {
		if n < 0 || n >= 99999 {
			n = 0
		}
		p.MaxAgeDays = shared.Int(n)
	}

	if src.PAMRead {
		p.Complexity = shared.Bool(hasQuality && requiresThreeClasses(qmod, qualityConf(qmod, quality)))
		p.History = shared.Int(passwordHistory(pam, parseKeyValueConf(src.PwHistory)))
		p.LockoutThreshold = shared.Int(lockoutThreshold(pam, parseKeyValueConf(src.Faillock)))
	}
	return nonZero(p)
}

// qualityConf is pwquality.conf for pam_pwquality; pam_cracklib only takes
// module arguments.
func qualityConf(e pamEntry, conf map[string]string) map[string]string {
	if e.module == "pam_pwquality.so" {
		return conf
	}
	return nil
}

func requiresThreeClasses(e pamEntry, conf map[string]string) bool {
	if n, ok := argOr(e, conf, "minclass"); ok && n >= 3 {
		return true
	}
	required := 0
	for _, k := range []string{"dcredit", "ucredit", "lcredit", "ocredit"} {
		if n, ok := argOr(e, conf, k); ok && n < 0 {
			required++
		}
	}
	return required >= 3
}

func passwordHistory(pam []pamEntry, conf map[string]string) int {
	if e, ok := findPAM(pam, "password", "pam_pwhistory.so"); ok {
		if n, ok := argOr(e, conf, "remember"); ok {
			return n
		}
		return 10
	}
	if e, ok := findPAM(pam, "password", "pam_unix.so"); ok {
		if n, ok := argOr(e, nil, "remember"); ok {
			return n
		}
	}
	return 0
}

func lockoutThreshold(pam []pamEntry, conf map[string]string) int {
	if e, ok := findPAM(pam, "auth", "pam_faillock.so"); ok {
		if n, ok := argOr(e, conf, "deny"); ok {
			return n
		}
		return 3
	}
	if e, ok := findPAM(pam, "auth", "pam_tally2.so"); ok {
		if n, ok := argOr(e, nil, "deny"); ok {
			return n
		}
	}
	return 0
}

// parseLoginDefs parses /etc/login.defs ("KEY value" lines).
func parseLoginDefs(content string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && !strings.HasPrefix(f[0], "#") {
			out[f[0]] = f[1]
		}
	}
	return out
}

// ── screen lock ───────────────────────────────────────────────────────────────

// loginSession is one row of `loginctl list-sessions --no-legend`.
type loginSession struct {
	ID   string
	UID  string
	User string
}

// parseLoginctlSessions reads `loginctl list-sessions --no-legend`
// ("SESSION UID USER SEAT TTY ...").
func parseLoginctlSessions(output string) []loginSession {
	var out []loginSession
	for _, line := range strings.Split(output, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 {
			out = append(out, loginSession{ID: f[0], UID: f[1], User: f[2]})
		}
	}
	return out
}

// isActiveGraphicalSession reads `loginctl show-session <id> -p Type -p
// Active` ("Type=wayland", "Active=yes").
func isActiveGraphicalSession(output string) bool {
	props := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			props[k] = v
		}
	}
	return (props["Type"] == "x11" || props["Type"] == "wayland") && props["Active"] == "yes"
}

// parseGSettingsUint reads a gsettings uint32 ("uint32 300" or "300").
func parseGSettingsUint(v string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "uint32")))
	return n, err == nil
}

// gnomeScreenLock builds screen_lock from the signed-in user's GNOME
// settings (gsettings output, "" when a read failed). The screen locks
// when org.gnome.desktop.screensaver lock-enabled is true, the lock screen
// isn't disabled by org.gnome.desktop.lockdown, and the session goes idle
// (org.gnome.desktop.session idle-delay > 0, 0 = never); it locks
// lock-delay seconds after the screen blanks, and always asks for the
// password. Nil when lock-enabled couldn't be read (not a GNOME desktop).
func gnomeScreenLock(lockEnabled, lockScreenDisabled, idleDelay, lockDelay string) *shared.ScreenLockInfo {
	if lockEnabled != "true" && lockEnabled != "false" {
		return nil
	}
	locks := lockEnabled == "true" && lockScreenDisabled != "true"
	info := &shared.ScreenLockInfo{RequirePasswordOnWake: shared.Bool(locks)}
	idle, ok := parseGSettingsUint(idleDelay)
	if !ok {
		return info
	}
	info.Enabled = shared.Bool(locks && idle > 0)
	if *info.Enabled {
		delay, _ := parseGSettingsUint(lockDelay)
		info.IdleTimeoutSeconds = shared.Int(idle + delay)
	}
	return info
}

// ── auto-login / guest ────────────────────────────────────────────────────────

// gdmAutoLogin reads GDM's custom.conf: [daemon] AutomaticLoginEnable or
// TimedLoginEnable.
func gdmAutoLogin(content string) bool {
	d := parseINI(content)["daemon"]
	return truthy(d["automaticloginenable"]) || truthy(d["timedloginenable"])
}

// lightdmLogin reads a LightDM config: autologin-user (or autologin-guest)
// in any seat section, and allow-guest.
func lightdmLogin(content string) (autoLogin, guest bool) {
	for _, sec := range parseINI(content) {
		if strings.TrimSpace(sec["autologin-user"]) != "" || truthy(sec["autologin-guest"]) {
			autoLogin = true
		}
		if truthy(sec["allow-guest"]) {
			guest = true
		}
	}
	return autoLogin, guest
}

// sddmAutoLogin reads an SDDM config: [Autologin] User=.
func sddmAutoLogin(content string) bool {
	return strings.TrimSpace(parseINI(content)["autologin"]["user"]) != ""
}

var gettyAutologinRe = regexp.MustCompile(`(?m)^\s*ExecStart\s*=.*(--autologin|\s-a\s)`)

// gettyAutoLogin reports whether a getty unit drop-in logs a user in on the
// console without a password (agetty --autologin).
func gettyAutoLogin(content string) bool {
	return gettyAutologinRe.MatchString(content)
}

// ── systemd units ─────────────────────────────────────────────────────────────

// parseUnitList reads `systemctl list-units --no-legend --plain` or
// `systemctl list-unit-files --no-legend --plain` output into
// unit name -> second column (load state, or the unit file state).
func parseUnitList(output string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		f := strings.Fields(strings.TrimLeft(line, "● *"))
		if len(f) >= 2 {
			out[f[0]] = f[1]
		}
	}
	return out
}

// anyUnit reports whether a unit whose name starts with one of prefixes is
// in units.
func anyUnit(units map[string]string, prefixes ...string) bool {
	for name := range units {
		for _, p := range prefixes {
			if strings.HasPrefix(name, p) {
				return true
			}
		}
	}
	return false
}

// smbMinProtocolAllowsSMB1 reads smb.conf's [global] server min protocol.
// Unset means Samba's default, SMB2_02 since Samba 4.11.
func smbMinProtocolAllowsSMB1(content string) bool {
	g := parseINI(content)["global"]
	v := g["server min protocol"]
	if v == "" {
		v = g["min protocol"]
	}
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "CORE", "COREPLUS", "LANMAN1", "LANMAN2", "NT1":
		return true
	}
	return false
}

// linuxRemoteAccess reports remote-access services from the active units.
// RDP means xrdp; NLA doesn't apply to it. smbConf is smb.conf.
func linuxRemoteAccess(active map[string]string, smbConf string) *shared.RemoteAccessInfo {
	smbd := anyUnit(active, "smbd.service", "smb.service")
	return &shared.RemoteAccessInfo{
		SSHEnabled:           shared.Bool(anyUnit(active, "ssh.service", "sshd.service", "ssh.socket", "sshd.socket")),
		RDPEnabled:           shared.Bool(anyUnit(active, "xrdp.service")),
		ScreenSharingEnabled: shared.Bool(anyUnit(active, "x11vnc", "vncserver", "tigervnc", "wayvnc", "gnome-remote-desktop")),
		SMB1Enabled:          shared.Bool(smbd && smbMinProtocolAllowsSMB1(smbConf)),
	}
}

// ── patching ──────────────────────────────────────────────────────────────────

// lastDpkgUpgrade returns the time of the last package upgrade in a dpkg.log
// ("2026-10-12 04:00:00 upgrade pkg:amd64 1.0 1.1"), in local time.
func lastDpkgUpgrade(content string, loc *time.Location) (time.Time, bool) {
	var last time.Time
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || f[2] != "upgrade" {
			continue
		}
		if t, err := time.ParseInLocation("2006-01-02 15:04:05", f[0]+" "+f[1], loc); err == nil && t.After(last) {
			last = t
		}
	}
	return last, !last.IsZero()
}

// lastDnfUpgrade returns the time of the last package upgrade in dnf's rpm
// transaction log ("2026-10-12T04:00:00+0000 SUBDEBUG Upgrade: bash-5.2...").
// Only Upgrade entries count: a fresh install of an application says
// nothing about whether the OS was patched.
func lastDnfUpgrade(content string) (time.Time, bool) {
	var last time.Time
	for _, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[2] != "Upgrade:" {
			continue
		}
		t, err := time.Parse("2006-01-02T15:04:05-0700", f[0])
		if err != nil {
			t, err = time.Parse(time.RFC3339, f[0])
		}
		if err == nil && t.After(last) {
			last = t
		}
	}
	return last, !last.IsZero()
}

// lastPacmanUpgrade returns the time of the last "upgraded" line in
// pacman.log: "[2026-10-12T04:00:00+0000] [ALPM] upgraded ..." (older
// pacman: "[2019-10-12 04:00] [ALPM] upgraded ...", local time).
func lastPacmanUpgrade(content string, loc *time.Location) (time.Time, bool) {
	var last time.Time
	for _, line := range strings.Split(content, "\n") {
		if !strings.Contains(line, "] upgraded ") || !strings.HasPrefix(line, "[") {
			continue
		}
		end := strings.IndexByte(line, ']')
		if end < 0 {
			continue
		}
		stamp := line[1:end]
		t, err := time.Parse("2006-01-02T15:04:05-0700", stamp)
		if err != nil {
			t, err = time.ParseInLocation("2006-01-02 15:04", stamp, loc)
		}
		if err == nil && t.After(last) {
			last = t
		}
	}
	return last, !last.IsZero()
}

// needrestartKernelPending reads `needrestart -b`: NEEDRESTART-KSTA is 1
// when the running kernel is current, 2 or 3 when a newer one is installed
// (0 = unknown).
func needrestartKernelPending(output string) (pending, ok bool) {
	for _, line := range strings.Split(output, "\n") {
		if v, found := strings.CutPrefix(strings.TrimSpace(line), "NEEDRESTART-KSTA:"); found {
			switch strings.TrimSpace(v) {
			case "1":
				return false, true
			case "2", "3":
				return true, true
			}
		}
	}
	return false, false
}

var (
	aptUnattendedRe    = regexp.MustCompile(`APT::Periodic::Unattended-Upgrade\s+"([^"]*)"`)
	aptBlockCommentRe  = regexp.MustCompile(`(?s)/\*.*?\*/`)
	aptLineCommentRe   = regexp.MustCompile(`(?m)//.*$`)
	aptHashCommentLine = regexp.MustCompile(`(?m)^\s*#.*$`)
)

// aptUnattendedEnabled reads the apt.conf.d files (concatenated in the order
// apt reads them, so the last setting wins) for APT::Periodic::Unattended-Upgrade.
// Comments (/* */, // and # lines) are removed first: apt ignores a
// commented-out setting, so it must not count here either.
func aptUnattendedEnabled(confs string) bool {
	confs = aptBlockCommentRe.ReplaceAllString(confs, "")
	confs = aptLineCommentRe.ReplaceAllString(confs, "")
	confs = aptHashCommentLine.ReplaceAllString(confs, "")
	m := aptUnattendedRe.FindAllStringSubmatch(confs, -1)
	return len(m) > 0 && strings.TrimSpace(m[len(m)-1][1]) != "0"
}

// dnfAutomaticApplies reads automatic.conf: [commands] apply_updates.
func dnfAutomaticApplies(conf string) bool {
	return truthy(parseINI(conf)["commands"]["apply_updates"])
}

// ── audit ─────────────────────────────────────────────────────────────────────

var auditKeyRe = regexp.MustCompile(`(?:-k\s+|key=)(\S+)`)

// parseAuditRules reads `auditctl -l`: the number of rules and their keys
// (sorted, unique), which the contract reports as audit categories.
func parseAuditRules(output string) (rules int, keys []string) {
	seen := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-") {
			continue // "No rules"
		}
		rules++
		if m := auditKeyRe.FindStringSubmatch(line); m != nil && m[1] != "(null)" && !seen[m[1]] {
			seen[m[1]] = true
			keys = append(keys, m[1])
		}
	}
	sort.Strings(keys)
	return rules, keys
}

// ── time sync ─────────────────────────────────────────────────────────────────

// timedatectlNTP reads `timedatectl show -p NTP` ("NTP=yes").
func timedatectlNTP(output string) (enabled, ok bool) {
	for _, line := range strings.Split(output, "\n") {
		if v, found := strings.CutPrefix(strings.TrimSpace(line), "NTP="); found {
			return v == "yes", true
		}
	}
	return false, false
}

// offsetMS converts seconds to whole milliseconds.
func offsetMS(seconds float64) *int64 {
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return nil
	}
	return shared.Int64(int64(math.Round(seconds * 1000)))
}

// parseChronyTracking reads `chronyc -c tracking`: field 2 is the source,
// field 5 the system clock's offset in seconds.
func parseChronyTracking(output string) (source string, offset *int64) {
	f := strings.Split(strings.TrimSpace(output), ",")
	if len(f) < 5 {
		return "", nil
	}
	if s, err := strconv.ParseFloat(f[4], 64); err == nil {
		offset = offsetMS(s)
	}
	return f[1], offset
}

// parseTimesyncStatus reads `timedatectl timesync-status`:
// "Server: 185.125.190.56 (ntp.ubuntu.com)" and "Offset: -1.234ms".
func parseTimesyncStatus(output string) (source string, offset *int64) {
	for _, line := range strings.Split(output, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Server":
			source = v
			if i, j := strings.IndexByte(v, '('), strings.LastIndexByte(v, ')'); i >= 0 && j > i {
				source = v[i+1 : j]
			}
		case "Offset":
			offset = parseSystemdTimespan(v)
		}
	}
	return source, offset
}

var timespanRe = regexp.MustCompile(`^([+-]?[0-9.]+)(us|µs|ms|s|min)$`)

// parseSystemdTimespan parses systemd's "-1.234ms" / "512us" / "+1.5s" into
// whole milliseconds.
func parseSystemdTimespan(v string) *int64 {
	m := timespanRe.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return nil
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return nil
	}
	scale := map[string]float64{"us": 1e-6, "µs": 1e-6, "ms": 1e-3, "s": 1, "min": 60}[m[2]]
	return offsetMS(n * scale)
}

// parseNtpqPeers reads `ntpq -pn`: the system peer is the line marked "*",
// and its offset column (ms) is the 9th.
func parseNtpqPeers(output string) (source string, offset *int64) {
	for _, line := range strings.Split(output, "\n") {
		if !strings.HasPrefix(line, "*") {
			continue
		}
		f := strings.Fields(line[1:])
		if len(f) < 9 {
			return "", nil
		}
		if ms, err := strconv.ParseFloat(f[8], 64); err == nil {
			offset = offsetMS(ms / 1000)
		}
		return f[0], offset
	}
	return "", nil
}

// ── backup ────────────────────────────────────────────────────────────────────

// linuxBackupUnits maps unit-name prefixes of common Linux backup tools to
// product names, in the order they are checked.
var linuxBackupUnits = []struct {
	prefix  string
	product string
}{
	{"veeamservice", "Veeam Agent for Linux"},
	{"acronis_mms", "Acronis Cyber Protect"},
	{"urbackupclientbackend", "UrBackup"},
	{"duplicati", "Duplicati"},
	{"bacula-fd", "Bacula"},
	{"bareos-fd", "Bareos"},
	{"borgmatic", "borgmatic"},
	{"restic", "restic"},
}

// linuxBackup reports the first backup tool with a unit file, enabled when
// that unit is. unitFiles is `systemctl list-unit-files` output parsed by
// parseUnitList. Nil when none is found.
func linuxBackup(unitFiles map[string]string) *shared.BackupInfo {
	names := make([]string, 0, len(unitFiles))
	for n := range unitFiles {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, b := range linuxBackupUnits {
		found, enabled := false, false
		for _, n := range names {
			if strings.HasPrefix(n, b.prefix) {
				found = true
				enabled = enabled || strings.HasPrefix(unitFiles[n], "enabled")
			}
		}
		if found {
			return &shared.BackupInfo{Product: b.product, Enabled: shared.Bool(enabled)}
		}
	}
	return nil
}
