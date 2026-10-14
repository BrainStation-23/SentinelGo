//go:build linux

package security

// Hermetic tests for the Linux compliance collector (#172), on the fake
// root and command stubs from security_linux_collect_test.go.

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

func stubLookupHomeDir(t *testing.T, homes map[string]string) {
	t.Helper()
	orig := lookupHomeDir
	t.Cleanup(func() { lookupHomeDir = orig })
	lookupHomeDir = func(uid string) (string, error) {
		if h, ok := homes[uid]; ok {
			return h, nil
		}
		return "", errors.New("unknown user")
	}
}

// gsettingsCmd is the command line collectLinuxScreenLock runs. env and
// gsettings are passed as resolved paths (fakeLookupBinary's).
func gsettingsCmd(key string) string {
	return "runuser -u alice -- /fixed/env HOME=/home/alice XDG_RUNTIME_DIR=/run/user/1000 " +
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus /fixed/gsettings get " + key
}

func complianceJSON(t *testing.T, info shared.SecurityInfo) map[string]string {
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

func TestApplyCompliance_UbuntuDesktop(t *testing.T) {
	root := stubLinuxSecurityRoot(t)
	writeRootFile(t, root, "/var/lib/dpkg/status", "")
	writeRootFile(t, root, "/var/log/dpkg.log", "2026-10-11 05:30:00 upgrade bash:amd64 5.1 5.2\n")
	writeRootFile(t, root, "/run/reboot-required", "")
	writeRootFile(t, root, "/usr/bin/unattended-upgrade", "")
	writeRootFile(t, root, "/etc/apt/apt.conf.d/20auto-upgrades", `APT::Periodic::Unattended-Upgrade "1";`+"\n")
	writeRootFile(t, root, "/etc/pam.d/common-password", debianCommonPassword)
	writeRootFile(t, root, "/etc/pam.d/common-auth", "auth required pam_faillock.so preauth deny=4\n")
	writeRootFile(t, root, "/etc/login.defs", "PASS_MAX_DAYS 99999\n")
	writeRootFile(t, root, "/etc/gdm3/custom.conf", "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=alice\n")
	writeRootFile(t, root, "/etc/audit/auditd.conf", "max_log_file = 8\n")
	writeRootFile(t, root, "/proc/1/comm", "systemd\n")
	writeRootFile(t, root, "/proc/2/comm", "auditd\n")
	writeRootFile(t, root, "/proc/3/comm", "systemd-timesyn\n")
	stubLookupHomeDir(t, map[string]string{"1000": "/home/alice"})

	stubLinuxSecurityCommands(t, map[string]linuxCmdResult{
		"systemctl list-units --state=active --no-legend --plain":      cmdOK("ssh.service loaded active running OpenBSD Secure Shell server\n"),
		"systemctl list-unit-files --no-legend --plain":                cmdOK("borgmatic.timer enabled enabled\nssh.service enabled enabled\n"),
		"loginctl list-sessions --no-legend":                           cmdOK("c1 120 gdm seat0 tty1\n2 1000 alice seat0 tty2\n"),
		"loginctl show-session c1 -p Type -p Active":                   cmdOK("Type=wayland\nActive=no\n"),
		"loginctl show-session 2 -p Type -p Active":                    cmdOK("Type=wayland\nActive=yes\n"),
		gsettingsCmd("org.gnome.desktop.screensaver lock-enabled"):     cmdOK("true\n"),
		gsettingsCmd("org.gnome.desktop.lockdown disable-lock-screen"): cmdOK("false\n"),
		gsettingsCmd("org.gnome.desktop.session idle-delay"):           cmdOK("uint32 300\n"),
		gsettingsCmd("org.gnome.desktop.screensaver lock-delay"):       cmdOK("uint32 0\n"),
		"auditctl -l":                 cmdOK("-w /etc/passwd -p wa -k identity\n"),
		"timedatectl show -p NTP":     cmdOK("NTP=yes\n"),
		"timedatectl timesync-status": cmdOK("Server: 185.125.190.56 (ntp.ubuntu.com)\nOffset: +2.4ms\n"),
	})

	var info shared.SecurityInfo
	applyCompliance(&info)
	got := complianceJSON(t, info)

	upgraded, _ := time.ParseInLocation("2006-01-02 15:04:05", "2026-10-11 05:30:00", time.Local)
	want := map[string]string{
		"screen_lock":           `{"enabled":true,"idle_timeout_seconds":300,"require_password_on_wake":true}`,
		"password_policy":       `{"min_length":12,"complexity":true,"max_age_days":0,"history":5,"lockout_threshold":4}`,
		"auto_login_enabled":    `true`,
		"guest_account_enabled": `false`,
		"remote_access":         `{"rdp_enabled":false,"smb1_enabled":false,"ssh_enabled":true,"screen_sharing_enabled":false}`,
		"patching":              `{"last_update_installed_at":"` + shared.ISOTime(upgraded) + `","pending_reboot":true,"auto_update_enabled":true}`,
		"audit_logging":         `{"enabled":true,"categories":["identity"],"log_max_size_mb":8}`,
		"time_sync":             `{"enabled":true,"source":"ntp.ubuntu.com","offset_ms":2}`,
		"backup":                `{"product":"borgmatic","enabled":true}`,
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s:\n got  %s\n want %s", k, got[k], w)
		}
	}
}

func TestApplyCompliance_RHELServer(t *testing.T) {
	root := stubLinuxSecurityRoot(t)
	mkRootDir(t, root, "/var/lib/rpm")
	writeRootFile(t, root, "/var/log/dnf.rpm.log", "2025-10-09T23:54:00+0000 SUBDEBUG Upgrade: bash-5.2.26-3.el9.x86_64\n")
	// A rotated log is read too; its newer fresh install must not count.
	writeRootFile(t, root, "/var/log/dnf.rpm.log.1", "2025-09-01T10:00:00+0000 SUBDEBUG Upgrade: openssl-3.0.7-28.el9.x86_64\n"+
		"2025-10-12T08:00:00+0000 SUBDEBUG Installed: newapp-1.0-1.el9.x86_64\n")
	writeRootFile(t, root, "/etc/pam.d/system-auth", rhelSystemAuth)
	writeRootFile(t, root, "/etc/security/pwquality.conf", "minlen = 14\nminclass = 3\n")
	writeRootFile(t, root, "/etc/dnf/automatic.conf", "[commands]\napply_updates = yes\n")
	writeRootFile(t, root, "/proc/1/comm", "systemd\n")
	writeRootFile(t, root, "/proc/2/comm", "chronyd\n")

	stubLinuxSecurityCommands(t, map[string]linuxCmdResult{
		"systemctl list-units --state=active --no-legend --plain": cmdOK("sshd.service loaded active running OpenSSH server daemon\n"),
		"systemctl list-unit-files --no-legend --plain":           cmdOK("dnf-automatic.timer enabled disabled\n"),
		"needs-restarting -r":                                     {out: "Reboot should not be necessary.\n", code: 0},
		"chronyc -c tracking":                                     cmdOK("A9FEA97B,169.254.169.123,4,1760054040.1,0.0000123,0,0,0,0,0,0,0,0,Normal\n"),
	})

	var info shared.SecurityInfo
	applyCompliance(&info)
	got := complianceJSON(t, info)

	want := map[string]string{
		"screen_lock":           `null`, // headless: no graphical session
		"password_policy":       `{"min_length":14,"complexity":true,"history":10,"lockout_threshold":5}`,
		"auto_login_enabled":    `false`,
		"guest_account_enabled": `false`,
		"remote_access":         `{"rdp_enabled":false,"smb1_enabled":false,"ssh_enabled":true,"screen_sharing_enabled":false}`,
		"patching":              `{"last_update_installed_at":"2025-10-09T23:54:00Z","pending_reboot":false,"auto_update_enabled":true}`,
		"audit_logging":         `{"enabled":false}`,
		"time_sync":             `{"enabled":true,"source":"169.254.169.123","offset_ms":0}`,
		"backup":                `null`,
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s:\n got  %s\n want %s", k, got[k], w)
		}
	}
}

// With no systemd, no package database and nothing readable, every key that
// can't be determined is left out rather than guessed.
func TestApplyCompliance_NothingReadable(t *testing.T) {
	stubLinuxSecurityRoot(t)
	stubLinuxSecurityCommands(t, nil)

	var info shared.SecurityInfo
	applyCompliance(&info)
	got := complianceJSON(t, info)
	for _, k := range []string{"screen_lock", "password_policy", "remote_access", "patching", "audit_logging", "time_sync", "backup"} {
		if got[k] != "null" {
			t.Errorf("%s = %s, want left out", k, got[k])
		}
	}
	// Autologin and guest come from config files whose absence is itself the
	// answer: nothing is configured.
	if got["auto_login_enabled"] != "false" || got["guest_account_enabled"] != "false" {
		t.Errorf("autologin=%s guest=%s", got["auto_login_enabled"], got["guest_account_enabled"])
	}
}
