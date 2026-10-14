package security

import (
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

// lookupHomeDir returns a user's home directory; a variable so tests don't
// depend on the host's accounts.
var lookupHomeDir = func(uid string) (string, error) {
	u, err := user.LookupId(uid)
	if err != nil {
		return "", err
	}
	return u.HomeDir, nil
}

// applyCompliance fills the compliance telemetry keys (#172).
func applyCompliance(info *shared.SecurityInfo) {
	active := systemdUnits("list-units", "--state=active")
	unitFiles := systemdUnits("list-unit-files")
	procs := runningProcNames()

	info.ScreenLock = collectLinuxScreenLock()
	info.PasswordPolicy = linuxPasswordPolicy(readLinuxPasswordSources())
	info.AutoLoginEnabled, info.GuestAccountEnabled = collectLinuxAutoLogin()
	if active != nil {
		smbConf, _ := readHostFile("/etc/samba/smb.conf")
		info.RemoteAccess = linuxRemoteAccess(active, smbConf)
	}
	info.Patching = collectLinuxPatching(unitFiles)
	info.AuditLogging = collectLinuxAuditLogging(procs)
	info.TimeSync = collectLinuxTimeSync(procs)
	if unitFiles != nil {
		info.Backup = linuxBackup(unitFiles)
	}
}

// readHostFile reads an absolute path under securityHostRoot.
func readHostFile(p string) (string, error) {
	data, err := os.ReadFile(securityHostRoot + p) // #nosec G304 -- fixed system paths
	return string(data), err
}

func hostFileExists(p string) bool {
	_, err := os.Stat(securityHostRoot + p)
	return err == nil
}

// readHostFiles concatenates the files matching each pattern, in pattern
// order and then name order (the order PAM, apt and pwquality read them).
func readHostFiles(patterns ...string) string {
	var b strings.Builder
	for _, pat := range patterns {
		matches, _ := filepath.Glob(securityHostRoot + pat)
		sort.Strings(matches)
		for _, m := range matches {
			if data, err := os.ReadFile(m); err == nil { // #nosec G304 -- glob of fixed system paths
				b.Write(data)
				b.WriteByte('\n')
			}
		}
	}
	return b.String()
}

// systemdUnits runs `systemctl <args> --no-legend --plain` and parses it with
// parseUnitList; nil when systemctl isn't available.
func systemdUnits(args ...string) map[string]string {
	out, err := securityRunCommand("systemctl", append(args, "--no-legend", "--plain")...)
	if err != nil {
		return nil
	}
	return parseUnitList(out)
}

// collectLinuxScreenLock reads the GNOME lock settings of the user in the
// active graphical session. Headless servers and machines with nobody
// signed in have no such session, so the key is left out there.
func collectLinuxScreenLock() *shared.ScreenLockInfo {
	s, ok := activeGraphicalSession()
	if !ok {
		return nil
	}
	home, err := lookupHomeDir(s.UID)
	if err != nil {
		return nil
	}
	// runuser and env would search PATH for the programs they start, so
	// those are passed resolved, and nothing runs when either isn't at its
	// fixed path.
	env, err := securityLookupBinary("env")
	if err != nil {
		return nil
	}
	gsettings, err := securityLookupBinary("gsettings")
	if err != nil {
		return nil
	}
	runtime := "/run/user/" + s.UID
	get := func(schema, key string) string {
		// gsettings reads the user's dconf database, so run it as that user
		// with their home and session bus.
		out, err := securityRunCommand("runuser", "-u", s.User, "--", env,
			"HOME="+home, "XDG_RUNTIME_DIR="+runtime,
			"DBUS_SESSION_BUS_ADDRESS=unix:path="+runtime+"/bus",
			gsettings, "get", schema, key)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(out)
	}
	return gnomeScreenLock(
		get("org.gnome.desktop.screensaver", "lock-enabled"),
		get("org.gnome.desktop.lockdown", "disable-lock-screen"),
		get("org.gnome.desktop.session", "idle-delay"),
		get("org.gnome.desktop.screensaver", "lock-delay"))
}

func activeGraphicalSession() (loginSession, bool) {
	out, err := securityRunCommand("loginctl", "list-sessions", "--no-legend")
	if err != nil {
		return loginSession{}, false
	}
	for _, s := range parseLoginctlSessions(out) {
		props, err := securityRunCommand("loginctl", "show-session", s.ID, "-p", "Type", "-p", "Active")
		if err == nil && isActiveGraphicalSession(props) {
			return s, true
		}
	}
	return loginSession{}, false
}

func readLinuxPasswordSources() linuxPasswordSources {
	var s linuxPasswordSources
	s.LoginDefs, _ = readHostFile("/etc/login.defs")
	s.PwQuality = readHostFiles("/etc/security/pwquality.conf", "/etc/security/pwquality.conf.d/*.conf")
	s.Faillock, _ = readHostFile("/etc/security/faillock.conf")
	s.PwHistory, _ = readHostFile("/etc/security/pwhistory.conf")
	// Debian/Ubuntu keep the shared stack in common-*; RHEL/Fedora/SUSE in
	// system-auth and password-auth.
	for _, f := range []string{"/etc/pam.d/common-password", "/etc/pam.d/common-auth", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth"} {
		if c, err := readHostFile(f); err == nil {
			s.PAM += c + "\n"
			s.PAMRead = true
		}
	}
	return s
}

// collectLinuxAutoLogin checks the display managers (GDM, LightDM, SDDM) and
// console getty drop-ins for automatic login, and LightDM for the guest
// session. Linux has no built-in guest account otherwise. Missing config
// files mean the feature isn't configured, so both are always reported.
func collectLinuxAutoLogin() (autoLogin, guest *bool) {
	auto, g := false, false
	for _, p := range []string{"/etc/gdm3/custom.conf", "/etc/gdm/custom.conf"} {
		if c, err := readHostFile(p); err == nil && gdmAutoLogin(c) {
			auto = true
		}
	}
	a, gl := lightdmLogin(readHostFiles("/usr/share/lightdm/lightdm.conf.d/*.conf", "/etc/lightdm/lightdm.conf", "/etc/lightdm/lightdm.conf.d/*.conf"))
	auto, g = auto || a, g || gl
	if sddmAutoLogin(readHostFiles("/etc/sddm.conf", "/etc/sddm.conf.d/*.conf")) {
		auto = true
	}
	if gettyAutoLogin(readHostFiles("/etc/systemd/system/getty@*.service.d/*.conf", "/etc/systemd/system/serial-getty@*.service.d/*.conf")) {
		auto = true
	}
	return shared.Bool(auto), shared.Bool(g)
}

func collectLinuxPatching(unitFiles map[string]string) *shared.PatchingInfo {
	var p shared.PatchingInfo
	if t, ok := linuxLastUpdate(); ok {
		p.LastUpdateInstalledAt = shared.ISOTime(t)
	}
	p.PendingReboot = linuxPendingReboot()
	p.AutoUpdateEnabled = linuxAutoUpdate(unitFiles)
	return nonZero(p)
}

func isDpkgSystem() bool { return hostFileExists("/var/lib/dpkg/status") }

func isRPMSystem() bool {
	return hostFileExists("/var/lib/rpm") || hostFileExists("/usr/lib/sysimage/rpm")
}

// linuxLastUpdate finds when packages were last upgraded: the dpkg log
// (current, then the previous rotation), dnf's rpm transaction log (all
// rotations), or pacman's log. Each source records upgrades separately from
// new installs. RPM systems without dnf's log (yum on EL7, dnf5) leave the
// key out: the rpm database only has install times, which a new application
// would reset.
func linuxLastUpdate() (time.Time, bool) {
	switch {
	case isDpkgSystem():
		for _, f := range []string{"/var/log/dpkg.log", "/var/log/dpkg.log.1"} {
			if c, err := readHostFile(f); err == nil {
				if t, ok := lastDpkgUpgrade(c, time.Local); ok {
					return t, true
				}
			}
		}
	case isRPMSystem():
		return lastDnfUpgrade(readHostFiles("/var/log/dnf.rpm.log*"))
	default:
		if c, err := readHostFile("/var/log/pacman.log"); err == nil {
			return lastPacmanUpgrade(c, time.Local)
		}
	}
	return time.Time{}, false
}

// linuxPendingReboot checks, in order: Debian/Ubuntu's reboot-required flag,
// RHEL's `needs-restarting -r` (exit 1 = reboot needed), and needrestart's
// kernel status. When none answers but Debian's flag mechanism is installed,
// a missing flag means no reboot is pending. Nil otherwise.
func linuxPendingReboot() *bool {
	if hostFileExists("/run/reboot-required") || hostFileExists("/var/run/reboot-required") {
		return shared.Bool(true)
	}
	if _, code, err := securityRunCommandOutput("needs-restarting", "-r"); err == nil && (code == 0 || code == 1) {
		return shared.Bool(code == 1)
	}
	if out, err := securityRunCommand("needrestart", "-b"); err == nil {
		if pending, ok := needrestartKernelPending(out); ok {
			return shared.Bool(pending)
		}
	}
	if hostFileExists("/usr/share/update-notifier/notify-reboot-required") {
		return shared.Bool(false)
	}
	return nil
}

// linuxAutoUpdate reports whether updates install unattended:
// unattended-upgrades on Debian/Ubuntu; dnf-automatic, dnf5-automatic or
// yum-cron set to apply updates on RPM systems.
func linuxAutoUpdate(unitFiles map[string]string) *bool {
	switch {
	case isDpkgSystem():
		installed := hostFileExists("/usr/bin/unattended-upgrade")
		return shared.Bool(installed && aptUnattendedEnabled(readHostFiles("/etc/apt/apt.conf.d/*")))
	case isRPMSystem() && unitFiles != nil:
		enabled := func(unit string) bool { return strings.HasPrefix(unitFiles[unit], "enabled") }
		applies := func(conf string) bool {
			c, _ := readHostFile(conf)
			return dnfAutomaticApplies(c)
		}
		on := enabled("dnf-automatic-install.timer") ||
			(enabled("dnf-automatic.timer") && applies("/etc/dnf/automatic.conf")) ||
			(enabled("dnf5-automatic.timer") && applies("/etc/dnf/dnf5-plugins/automatic.conf")) ||
			(enabled("yum-cron.service") && applies("/etc/yum/yum-cron.conf"))
		return shared.Bool(on)
	}
	return nil
}

// collectLinuxAuditLogging reports whether auditd is running, the keys of
// its loaded rules, and max_log_file (MB) from auditd.conf.
func collectLinuxAuditLogging(procs map[string]bool) *shared.AuditLoggingInfo {
	running := procs["auditd"]
	conf, confErr := readHostFile("/etc/audit/auditd.conf")
	if len(procs) == 0 && confErr != nil {
		return nil
	}
	a := &shared.AuditLoggingInfo{Enabled: shared.Bool(running)}
	if running {
		if out, err := securityRunCommand("auditctl", "-l"); err == nil {
			_, a.Categories = parseAuditRules(out)
		}
	}
	if n, err := strconv.Atoi(parseKeyValueConf(conf)["max_log_file"]); err == nil {
		a.LogMaxSizeMB = shared.Int(n)
	}
	return a
}

// collectLinuxTimeSync reads timedatectl's NTP switch and the running time
// daemon's source and offset: chronyd, ntpd or systemd-timesyncd (whose
// /proc comm is truncated to 15 characters).
func collectLinuxTimeSync(procs map[string]bool) *shared.TimeSyncInfo {
	var t shared.TimeSyncInfo
	if out, err := securityRunCommand("timedatectl", "show", "-p", "NTP"); err == nil {
		if on, ok := timedatectlNTP(out); ok {
			t.Enabled = shared.Bool(on)
		}
	}
	daemon := true
	switch {
	case procs["chronyd"]:
		if out, err := securityRunCommand("chronyc", "-c", "tracking"); err == nil {
			t.Source, t.OffsetMS = parseChronyTracking(out)
		}
	case procs["ntpd"]:
		if out, err := securityRunCommand("ntpq", "-pn"); err == nil {
			t.Source, t.OffsetMS = parseNtpqPeers(out)
		}
	case procs["systemd-timesyn"]:
		if out, err := securityRunCommand("timedatectl", "timesync-status"); err == nil {
			t.Source, t.OffsetMS = parseTimesyncStatus(out)
		}
	default:
		daemon = false
	}
	if t.Enabled == nil && len(procs) > 0 {
		t.Enabled = shared.Bool(daemon)
	}
	return nonZero(t)
}
