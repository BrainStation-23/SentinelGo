package security

import (
	"strconv"
	"strings"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

// applyCompliance fills the compliance telemetry keys (#172). macOS reports
// no pending_reboot or missing_updates: neither has a local source that
// doesn't need a slow, networked `softwareupdate -l`.
func applyCompliance(info *shared.SecurityInfo) {
	info.ScreenLock = collectMacScreenLock()
	info.PasswordPolicy = collectMacPasswordPolicy()
	info.AutoLoginEnabled, info.GuestAccountEnabled = collectMacLoginWindow()
	info.RemoteAccess = collectMacRemoteAccess()
	info.Patching = collectMacPatching()
	info.AuditLogging = collectMacAuditLogging()
	info.TimeSync = collectMacTimeSync()
	info.Backup = collectMacBackup()
	info.ApplicationControl = collectMacAppControl()
}

// collectMacAppControl reports Gatekeeper. spctl exits 1 when assessments
// are disabled, so the output is read whatever the exit code. macOS has no
// AutoRun, so security_info.autorun is never sent.
func collectMacAppControl() *shared.ApplicationControlInfo {
	out, _, err := darwinRunCommandOutput("spctl", "--status")
	if err != nil {
		return nil
	}
	return gatekeeperControl(out)
}

// readPlist converts a plist file (binary or XML) to XML with plutil and
// decodes it; nil when the file is missing or unreadable.
func readPlist(path string) any {
	out, err := darwinRunCommand("plutil", "-convert", "xml1", "-o", "-", path)
	if err != nil {
		return nil
	}
	v, err := shared.DecodePlistXML([]byte(out))
	if err != nil {
		return nil
	}
	return v
}

// readPrefs reads a preference domain: the managed (MDM) values win over
// the local file's.
func readPrefs(local string, managed ...string) map[string]any {
	merged := map[string]any{}
	paths := append([]string{local}, managed...)
	for _, p := range paths {
		if m, ok := readPlist(p).(map[string]any); ok {
			for k, v := range m {
				merged[k] = v
			}
		}
	}
	return merged
}

// consoleUser returns the user signed in at the console and their uid; ok is
// false at the login window.
func consoleUser() (name, uid string, ok bool) {
	out, err := darwinRunCommand("stat", "-f", "%Su", "/dev/console")
	name = strings.TrimSpace(out)
	if err != nil || name == "" || name == "root" || name == "loginwindow" || strings.HasPrefix(name, "_") {
		return "", "", false
	}
	idOut, err := darwinRunCommand("id", "-u", name)
	if err != nil {
		return "", "", false
	}
	return name, strings.TrimSpace(idOut), true
}

// asUser runs a command in the console user's session; preference reads and
// sysadminctl -screenLock only answer for the user they run as. launchctl
// and sudo would search PATH for the programs they start, so sudo and the
// command are passed resolved, and the call is skipped when either isn't
// at its fixed path.
func asUser(name, uid, cmd string, args ...string) (string, int, error) {
	sudo, err := darwinLookupBinary("sudo")
	if err != nil {
		return "", -1, err
	}
	bin, err := darwinLookupBinary(cmd)
	if err != nil {
		return "", -1, err
	}
	full := append([]string{"asuser", uid, sudo, "-u", name, bin}, args...)
	return darwinRunCommandOutput("launchctl", full...)
}

func collectMacScreenLock() *shared.ScreenLockInfo {
	name, uid, ok := consoleUser()
	if !ok {
		return nil
	}
	managed := readPrefs("/Library/Managed Preferences/com.apple.screensaver.plist",
		"/Library/Managed Preferences/"+name+"/com.apple.screensaver.plist")

	saverIdle := -1
	if n, ok := shared.PlistInt(managed["idleTime"]); ok {
		saverIdle = n
	} else if out, code, err := asUser(name, uid, "defaults", "-currentHost", "read", "com.apple.screensaver", "idleTime"); err == nil && code == 0 {
		if n, err := strconv.Atoi(strings.TrimSpace(out)); err == nil {
			saverIdle = n
		}
	}

	displaySleep := -1
	if out, err := darwinRunCommand("pmset", "-g"); err == nil {
		if n, ok := parsePmsetDisplaySleep(out); ok {
			displaySleep = n
		}
	}

	password, delay := macPasswordAfterLock(name, uid, managed)
	return macScreenLock(saverIdle, displaySleep, password, delay)
}

// macPasswordAfterLock resolves whether a password is needed after the
// screen saver or sleep, and the grace delay. A managed profile wins for
// each value it sets; whatever it leaves unset comes from the user's own
// setting (sysadminctl). delay is -1 when it can't be determined.
func macPasswordAfterLock(name, uid string, managed map[string]any) (password *bool, delay int) {
	delay = -1
	if b, ok := shared.PlistBool(managed["askForPassword"]); ok {
		password = shared.Bool(b)
	}
	if n, ok := shared.PlistInt(managed["askForPasswordDelay"]); ok {
		delay = n
	}
	if password != nil && delay >= 0 {
		return password, delay
	}
	if out, _, err := asUser(name, uid, "sysadminctl", "-screenLock", "status"); err == nil {
		if required, d, ok := parseSysadminctlScreenLock(out); ok {
			if password == nil {
				password = shared.Bool(required)
			}
			if delay < 0 && required {
				delay = d
			}
		}
	}
	return password, delay
}

func collectMacPasswordPolicy() *shared.PasswordPolicyInfo {
	// pwpolicy can exit non-zero when no policy is set; the output decides.
	out, _, err := darwinRunCommandOutput("pwpolicy", "-getaccountpolicies")
	if err != nil {
		return nil
	}
	return macPasswordPolicy(out)
}

// collectMacLoginWindow reads autoLoginUser and GuestEnabled from the login
// window preferences. Without the file, or without the key, neither is
// configured (macOS leaves the guest account off by default); a
// GuestEnabled value that isn't a boolean leaves guest unknown.
func collectMacLoginWindow() (autoLogin, guest *bool) {
	const path = "/Library/Preferences/com.apple.loginwindow.plist"
	if _, err := darwinStat(path); err != nil {
		return shared.Bool(false), shared.Bool(false)
	}
	prefs, ok := readPlist(path).(map[string]any)
	if !ok {
		return nil, nil
	}
	user, _ := prefs["autoLoginUser"].(string)
	autoLogin = shared.Bool(strings.TrimSpace(user) != "")
	raw, set := prefs["GuestEnabled"]
	if !set {
		return autoLogin, shared.Bool(false)
	}
	if g, ok := shared.PlistBool(raw); ok {
		guest = shared.Bool(g)
	}
	return autoLogin, guest
}

// launchdLoaded reports whether a system launchd job is loaded, which for
// sshd and screensharing means the sharing service is turned on.
func launchdLoaded(label string) (loaded, ok bool) {
	_, code, err := darwinRunCommandOutput("launchctl", "print", "system/"+label)
	if err != nil {
		return false, false
	}
	return code == 0, true
}

// collectMacRemoteAccess reports Remote Login (sshd) and Screen Sharing,
// which Remote Management (ARD) also turns on.
func collectMacRemoteAccess() *shared.RemoteAccessInfo {
	ssh, ok := launchdLoaded("com.openssh.sshd")
	if !ok {
		return nil
	}
	screen, _ := launchdLoaded("com.apple.screensharing")
	if data, err := darwinReadFile("/Library/Application Support/Apple/Remote Desktop/RemoteManagement.launchd"); err == nil &&
		strings.Contains(string(data), "enabled") {
		screen = true
	}
	return &shared.RemoteAccessInfo{SSHEnabled: shared.Bool(ssh), ScreenSharingEnabled: shared.Bool(screen)}
}

func collectMacPatching() *shared.PatchingInfo {
	var p shared.PatchingInfo
	if t, ok := macLastUpdate(readPlist("/Library/Receipts/InstallHistory.plist")); ok {
		p.LastUpdateInstalledAt = shared.ISOTime(t)
	}
	prefs := readPrefs("/Library/Preferences/com.apple.SoftwareUpdate.plist",
		"/Library/Managed Preferences/com.apple.SoftwareUpdate.plist")
	p.AutoUpdateEnabled = shared.Bool(macAutoUpdate(prefs))
	return &p
}

// collectMacAuditLogging reads the OpenBSM audit flags and whether auditd is
// loaded. Recent macOS releases deprecate OpenBSM; without audit_control the
// key is left out.
func collectMacAuditLogging() *shared.AuditLoggingInfo {
	data, err := darwinReadFile("/etc/security/audit_control")
	if err != nil {
		return nil
	}
	flags, _ := parseAuditControl(string(data))
	loaded, _ := launchdLoaded("com.apple.auditd")
	return &shared.AuditLoggingInfo{Enabled: shared.Bool(loaded && len(flags) > 0), Categories: flags}
}

func collectMacTimeSync() *shared.TimeSyncInfo {
	var t shared.TimeSyncInfo
	if out, err := darwinRunCommand("systemsetup", "-getusingnetworktime"); err == nil {
		switch strings.ToLower(colonValue(out)) {
		case "on":
			t.Enabled = shared.Bool(true)
		case "off":
			t.Enabled = shared.Bool(false)
		}
	}
	if out, err := darwinRunCommand("systemsetup", "-getnetworktimeserver"); err == nil && t.Enabled != nil {
		t.Source = colonValue(out)
	}
	return nonZero(t)
}

// timeMachineBackup reports a configured Time Machine: enabled when
// automatic backups are on, with the time of the latest backup.
func timeMachineBackup() *shared.BackupInfo {
	b := &shared.BackupInfo{Product: "Time Machine"}
	if prefs, ok := readPlist("/Library/Preferences/com.apple.TimeMachine.plist").(map[string]any); ok {
		if on, ok := shared.PlistBool(prefs["AutoBackup"]); ok {
			b.Enabled = shared.Bool(on)
		}
	}
	if out, err := darwinRunCommand("tmutil", "latestbackup"); err == nil {
		if t, ok := parseTimeMachineLatest(out, time.Local); ok {
			b.LastSuccessAt = shared.ISOTime(t)
		}
	}
	return b
}

// macBackupApps are third-party backup apps, checked when Time Machine has
// no destination.
var macBackupApps = []struct {
	path    string
	product string
}{
	{"/Library/Backblaze.bzpkg", "Backblaze"},
	{"/Applications/Code42.app", "Code42"},
	{"/Applications/CrashPlan.app", "CrashPlan"},
	{"/Applications/Arq.app", "Arq"},
}

// collectMacBackup reports Time Machine when it has a destination (enabled
// when automatic backups are on), else a known third-party app, else Time
// Machine as off.
func collectMacBackup() *shared.BackupInfo {
	dest, err := darwinRunCommand("tmutil", "destinationinfo")
	if err == nil && tmHasDestination(dest) {
		return timeMachineBackup()
	}
	for _, app := range macBackupApps {
		if _, statErr := darwinStat(app.path); statErr == nil {
			return &shared.BackupInfo{Product: app.product}
		}
	}
	if err == nil {
		return &shared.BackupInfo{Product: "Time Machine", Enabled: shared.Bool(false)}
	}
	return nil
}
