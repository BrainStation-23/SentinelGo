package security

// Hermetic tests for the macOS compliance collector (#172), using the
// stubDarwinProcesses and stubDarwinSecurityFS seams.

import (
	"encoding/json"
	"strings"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

func plistXML(body string) string {
	return `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0">` + body + `</plist>`
}

func plutilCmd(path string) string { return "plutil -convert xml1 -o - " + path }

// asAlice is the command line asUser runs for alice: sudo and the command
// are passed as resolved paths (fakeLookupBinary's).
func asAlice(cmd string) string {
	name, args, _ := strings.Cut(cmd, " ")
	return "launchctl asuser 501 /fixed/sudo -u alice /fixed/" + name + " " + args
}

func darwinComplianceJSON(t *testing.T, info shared.SecurityInfo) map[string]string {
	t.Helper()
	out := map[string]string{}
	for k, v := range map[string]any{
		"screen_lock": info.ScreenLock, "password_policy": info.PasswordPolicy,
		"auto_login_enabled": info.AutoLoginEnabled, "guest_account_enabled": info.GuestAccountEnabled,
		"remote_access": info.RemoteAccess, "patching": info.Patching, "audit_logging": info.AuditLogging,
		"time_sync": info.TimeSync, "backup": info.Backup,
	} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		out[k] = string(b)
	}
	return out
}

func TestApplyCompliance_DarwinSignedIn(t *testing.T) {
	const loginwindow = "/Library/Preferences/com.apple.loginwindow.plist"
	stubDarwinSecurityFS(t, []string{loginwindow}, nil)
	stubDarwinProcesses(t, map[string]fakeProc{
		"stat -f %Su /dev/console": {stdout: "alice\n"},
		"id -u alice":              {stdout: "501\n"},
		asAlice("defaults -currentHost read com.apple.screensaver idleTime"): {stdout: "1200\n"},
		"pmset -g": {stdout: "System-wide power settings:\nCurrently in use:\n displaysleep         5\n"},
		asAlice("sysadminctl -screenLock status"):        {stderr: "2026-10-14 10:00:00.000 sysadminctl[1:2] screenLock delay is immediate\n"},
		"pwpolicy -getaccountpolicies":                   {stdout: pwpolicySample},
		plutilCmd(loginwindow):                           {stdout: plistXML(`<dict><key>GuestEnabled</key><false/><key>lastUserName</key><string>alice</string></dict>`)},
		"launchctl print system/com.openssh.sshd":        {stdout: "system/com.openssh.sshd = {\n"},
		"launchctl print system/com.apple.screensharing": {stderr: "Could not find service", exit: 113},
		plutilCmd("/Library/Receipts/InstallHistory.plist"): {stdout: plistXML(`<array>
<dict><key>date</key><date>2026-10-02T18:30:00Z</date><key>displayName</key><string>macOS 15.7.1</string><key>processName</key><string>softwareupdated</string></dict>
</array>`)},
		plutilCmd("/Library/Preferences/com.apple.SoftwareUpdate.plist"): {stdout: plistXML(`<dict><key>AutomaticCheckEnabled</key><true/><key>AutomaticallyInstallMacOSUpdates</key><true/></dict>`)},
		"systemsetup -getusingnetworktime":                               {stdout: "Network Time: On\n"},
		"systemsetup -getnetworktimeserver":                              {stdout: "Network Time Server: time.apple.com\n"},
		"tmutil destinationinfo":                                         {stdout: "====\nName          : Backup\nKind          : Local\n"},
		plutilCmd("/Library/Preferences/com.apple.TimeMachine.plist"):    {stdout: plistXML(`<dict><key>AutoBackup</key><true/></dict>`)},
		"tmutil latestbackup":                                            {stdout: "/Volumes/Backup/Backups.backupdb/mac/2026-10-14-010000\n"},
	})

	var info shared.SecurityInfo
	applyCompliance(&info)
	got := darwinComplianceJSON(t, info)

	want := map[string]string{
		"screen_lock":           `{"enabled":true,"idle_timeout_seconds":300,"require_password_on_wake":true}`,
		"password_policy":       `{"min_length":12,"complexity":true,"max_age_days":90,"history":5,"lockout_threshold":10}`,
		"auto_login_enabled":    `false`,
		"guest_account_enabled": `false`,
		"remote_access":         `{"ssh_enabled":true,"screen_sharing_enabled":false}`,
		"patching":              `{"last_update_installed_at":"2026-10-02T18:30:00Z","auto_update_enabled":true}`,
		"audit_logging":         `null`, // no audit_control on current macOS
		"time_sync":             `{"enabled":true,"source":"time.apple.com"}`,
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s:\n got  %s\n want %s", k, got[k], w)
		}
	}
	// last_success_at is local time, so only its presence is checked.
	if info.Backup == nil || info.Backup.Product != "Time Machine" || info.Backup.Enabled == nil ||
		!*info.Backup.Enabled || info.Backup.LastSuccessAt == "" {
		t.Errorf("backup = %s", got["backup"])
	}
}

// At the login window there is no console user, and with nothing else
// readable, keys are left out rather than guessed.
func TestApplyCompliance_DarwinLoginWindow(t *testing.T) {
	stubDarwinSecurityFS(t, nil, map[string]string{"/etc/security/audit_control": "dir:/var/audit\nflags:lo,aa\n"})
	stubDarwinProcesses(t, map[string]fakeProc{
		"stat -f %Su /dev/console":                {stdout: "root\n"},
		"launchctl print system/com.apple.auditd": {exit: 113},
		"tmutil destinationinfo":                  {stdout: "No destinations configured.\n"},
	})

	var info shared.SecurityInfo
	applyCompliance(&info)
	got := darwinComplianceJSON(t, info)

	want := map[string]string{
		"screen_lock":           `null`,
		"password_policy":       `null`,
		"auto_login_enabled":    `false`, // no loginwindow plist: nothing configured
		"guest_account_enabled": `false`,
		"remote_access":         `null`,
		"patching":              `{"auto_update_enabled":false}`, // installing macOS updates defaults to off
		"audit_logging":         `{"enabled":false,"categories":["lo","aa"]}`,
		"time_sync":             `null`,
		"backup":                `{"product":"Time Machine","enabled":false}`,
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s:\n got  %s\n want %s", k, got[k], w)
		}
	}
}

func TestCollectMacLoginWindow_AutoLogin(t *testing.T) {
	const loginwindow = "/Library/Preferences/com.apple.loginwindow.plist"
	stubDarwinSecurityFS(t, []string{loginwindow}, nil)
	stubDarwinProcesses(t, map[string]fakeProc{
		plutilCmd(loginwindow): {stdout: plistXML(`<dict><key>autoLoginUser</key><string>kiosk</string><key>GuestEnabled</key><integer>1</integer></dict>`)},
	})
	auto, guest := collectMacLoginWindow()
	if auto == nil || !*auto || guest == nil || !*guest {
		t.Errorf("auto=%v guest=%v", auto, guest)
	}
}

// A GuestEnabled value that isn't a boolean leaves guest unknown; a missing
// one is macOS' default, off.
func TestCollectMacLoginWindow_Guest(t *testing.T) {
	const loginwindow = "/Library/Preferences/com.apple.loginwindow.plist"
	for _, c := range []struct{ dict, want string }{
		{`<key>lastUserName</key><string>alice</string>`, "false"},
		{`<key>GuestEnabled</key><string>maybe</string>`, "null"},
		{`<key>GuestEnabled</key><false/>`, "false"},
	} {
		stubDarwinSecurityFS(t, []string{loginwindow}, nil)
		stubDarwinProcesses(t, map[string]fakeProc{
			plutilCmd(loginwindow): {stdout: plistXML(`<dict>` + c.dict + `</dict>`)},
		})
		_, guest := collectMacLoginWindow()
		if b, _ := json.Marshal(guest); string(b) != c.want {
			t.Errorf("%s: guest = %s, want %s", c.dict, b, c.want)
		}
	}
}

func TestCollectMacScreenLock_ManagedProfileWins(t *testing.T) {
	stubDarwinSecurityFS(t, nil, nil)
	stubDarwinProcesses(t, map[string]fakeProc{
		"stat -f %Su /dev/console": {stdout: "alice\n"},
		"id -u alice":              {stdout: "501\n"},
		"pmset -g":                 {stdout: " displaysleep         0\n"},
		plutilCmd("/Library/Managed Preferences/com.apple.screensaver.plist"): {stdout: plistXML(
			`<dict><key>idleTime</key><integer>600</integer><key>askForPassword</key><integer>1</integer><key>askForPasswordDelay</key><integer>5</integer></dict>`)},
		// The user's own settings say otherwise; MDM must win.
		asAlice("defaults -currentHost read com.apple.screensaver idleTime"): {stdout: "0\n"},
		asAlice("sysadminctl -screenLock status"):                            {stderr: "screenLock is off\n"},
	})
	b, _ := json.Marshal(collectMacScreenLock())
	if string(b) != `{"enabled":true,"idle_timeout_seconds":605,"require_password_on_wake":true}` {
		t.Errorf("screen_lock = %s", b)
	}
}

// A profile that requires a password but sets no delay must not be read as
// "immediately": the user's own delay still applies.
func TestCollectMacScreenLock_ManagedPasswordWithoutDelay(t *testing.T) {
	stubDarwinSecurityFS(t, nil, nil)
	stubDarwinProcesses(t, map[string]fakeProc{
		"stat -f %Su /dev/console": {stdout: "alice\n"},
		"id -u alice":              {stdout: "501\n"},
		"pmset -g":                 {stdout: " displaysleep         0\n"},
		plutilCmd("/Library/Managed Preferences/com.apple.screensaver.plist"): {stdout: plistXML(
			`<dict><key>idleTime</key><integer>600</integer><key>askForPassword</key><true/></dict>`)},
		asAlice("sysadminctl -screenLock status"): {stderr: "screenLock delay is 300 seconds\n"},
	})
	b, _ := json.Marshal(collectMacScreenLock())
	if string(b) != `{"enabled":true,"idle_timeout_seconds":900,"require_password_on_wake":true}` {
		t.Errorf("screen_lock = %s", b)
	}
}
