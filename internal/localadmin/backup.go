package localadmin

// The backup for an expiry: a one-shot OS task that runs
// "sentinelgo local-admin expire <grant_id>" at the end time, in case the
// user (an administrator until then) stops the agent. The agent's own timer
// stays the primary path; the task does nothing if the grant is already
// removed.
//
// Windows: Task Scheduler, as SYSTEM, run as soon as possible if missed.
// macOS: a LaunchDaemon with StartCalendarInterval (launchd runs a missed
// calendar job after wake). Linux: a systemd timer with Persistent=true.

import (
	"context"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Backup schedules and cancels the OS task for a grant.
type Backup interface {
	Schedule(ctx context.Context, grantID string, at time.Time) error
	Cancel(ctx context.Context, grantID string) error
}

// BackupFor returns the backup for goos, starting exe.
func BackupFor(goos string, run Runner, exe string) Backup {
	switch goos {
	case "windows":
		return &winBackup{run: run, exe: exe}
	case "darwin":
		return &launchdBackup{run: run, exe: exe, dir: "/Library/LaunchDaemons"}
	case "linux":
		return &systemdBackup{run: run, exe: exe, dir: "/etc/systemd/system"}
	}
	return noBackup{}
}

type noBackup struct{}

func (noBackup) Schedule(context.Context, string, time.Time) error { return nil }
func (noBackup) Cancel(context.Context, string) error              { return nil }

// ExpireArgs are the arguments the backup task passes to the agent.
func ExpireArgs(grantID string) []string { return []string{"local-admin", "expire", grantID} }

// ── Windows ──────────────────────────────────────────────────────────────────

// The time is parsed with the invariant culture: schtasks /SD depends on the
// system's date format.
const winScheduleScript = `$ErrorActionPreference = 'Stop'
$at = [DateTimeOffset]::Parse($env:SG_AT, [Globalization.CultureInfo]::InvariantCulture).LocalDateTime
$a = New-ScheduledTaskAction -Execute $env:SG_EXE -Argument ('local-admin expire ' + $env:SG_GRANT)
$t = New-ScheduledTaskTrigger -Once -At $at
$s = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$p = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName ('LocalAdminExpire-' + $env:SG_GRANT) -TaskPath '\SentinelGo\' -Action $a -Trigger $t -Settings $s -Principal $p -Force | Out-Null`

const winCancelScript = `Unregister-ScheduledTask -TaskName ('LocalAdminExpire-' + $env:SG_GRANT) -TaskPath '\SentinelGo\' -Confirm:$false -ErrorAction SilentlyContinue`

type winBackup struct {
	run Runner
	exe string
}

func (b *winBackup) Schedule(ctx context.Context, id string, at time.Time) error {
	if !ValidGrantID(id) {
		return fmt.Errorf("bad grant id")
	}
	_, err := powershell(ctx, b.run, winScheduleScript,
		"SG_AT="+at.UTC().Format(time.RFC3339), "SG_EXE="+b.exe, "SG_GRANT="+id)
	return err
}

func (b *winBackup) Cancel(ctx context.Context, id string) error {
	if !ValidGrantID(id) {
		return fmt.Errorf("bad grant id")
	}
	_, err := powershell(ctx, b.run, winCancelScript, "SG_GRANT="+id)
	return err
}

// ── macOS ────────────────────────────────────────────────────────────────────

type launchdBackup struct {
	run Runner
	exe string
	dir string
}

func launchdLabel(id string) string { return "com.sentinelgo.localadmin." + id }

func (b *launchdBackup) plistPath(id string) string {
	return filepath.Join(b.dir, launchdLabel(id)+".plist")
}

// launchdPlist fires once a year at at's local month, day, hour and minute,
// rounded up to the next minute so it never runs early. The expire command
// removes the job, and does nothing for a grant already removed.
func launchdPlist(label, exe, id string, at time.Time) string {
	at = at.Local()
	if at.Second() > 0 || at.Nanosecond() > 0 {
		at = at.Truncate(time.Minute).Add(time.Minute)
	}
	var args strings.Builder
	for _, a := range append([]string{exe}, ExpireArgs(id)...) {
		fmt.Fprintf(&args, "\n    <string>%s</string>", html.EscapeString(a))
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>%s</string>
  <key>ProgramArguments</key>
  <array>%s
  </array>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Month</key><integer>%d</integer>
    <key>Day</key><integer>%d</integer>
    <key>Hour</key><integer>%d</integer>
    <key>Minute</key><integer>%d</integer>
  </dict>
</dict>
</plist>
`, html.EscapeString(label), args.String(), int(at.Month()), at.Day(), at.Hour(), at.Minute())
}

func (b *launchdBackup) Schedule(ctx context.Context, id string, at time.Time) error {
	if !ValidGrantID(id) {
		return fmt.Errorf("bad grant id")
	}
	_ = b.Cancel(ctx, id) // an extension replaces the job
	p := b.plistPath(id)
	if err := os.WriteFile(p, []byte(launchdPlist(launchdLabel(id), b.exe, id, at)), 0o644); err != nil { // #nosec G306 -- launchd requires a world-readable, root-owned plist
		return err
	}
	_, err := b.run(ctx, "launchctl", []string{"bootstrap", "system", p}, nil)
	return err
}

// Cancel deletes the plist first, then unloads the job: when the job itself
// runs this, bootout ends it, and the plist must already be gone by then.
func (b *launchdBackup) Cancel(ctx context.Context, id string) error {
	if !ValidGrantID(id) {
		return fmt.Errorf("bad grant id")
	}
	err := os.Remove(b.plistPath(id))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	_, _ = b.run(ctx, "launchctl", []string{"bootout", "system/" + launchdLabel(id)}, nil)
	return nil
}

// ── Linux ────────────────────────────────────────────────────────────────────

type systemdBackup struct {
	run Runner
	exe string
	dir string
}

func systemdUnit(id string) string { return "sentinelgo-local-admin-" + id }

// systemdQuote quotes an ExecStart argument.
func systemdQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%").Replace(s) + `"`
}

func systemdFiles(exe, id string, at time.Time) (service, timer string) {
	var exec []string
	for _, a := range append([]string{exe}, ExpireArgs(id)...) {
		exec = append(exec, systemdQuote(a))
	}
	service = fmt.Sprintf(`[Unit]
Description=SentinelGo: end a time-limited administrator grant
[Service]
Type=oneshot
ExecStart=%s
`, strings.Join(exec, " "))
	timer = fmt.Sprintf(`[Unit]
Description=SentinelGo: end a time-limited administrator grant
[Timer]
OnCalendar=%s
Persistent=true
AccuracySec=1s
[Install]
WantedBy=timers.target
`, at.UTC().Format("2006-01-02 15:04:05")+" UTC")
	return service, timer
}

func (b *systemdBackup) Schedule(ctx context.Context, id string, at time.Time) error {
	if !ValidGrantID(id) {
		return fmt.Errorf("bad grant id")
	}
	_ = b.Cancel(ctx, id) // an extension replaces the timer
	unit := systemdUnit(id)
	svc, tmr := systemdFiles(b.exe, id, at)
	if err := os.WriteFile(filepath.Join(b.dir, unit+".service"), []byte(svc), 0o644); err != nil { // #nosec G306 -- systemd unit files are world-readable
		return err
	}
	if err := os.WriteFile(filepath.Join(b.dir, unit+".timer"), []byte(tmr), 0o644); err != nil { // #nosec G306 -- as above
		return err
	}
	if _, err := b.run(ctx, "systemctl", []string{"daemon-reload"}, nil); err != nil {
		return err
	}
	_, err := b.run(ctx, "systemctl", []string{"enable", "--now", unit + ".timer"}, nil)
	return err
}

func (b *systemdBackup) Cancel(ctx context.Context, id string) error {
	if !ValidGrantID(id) {
		return fmt.Errorf("bad grant id")
	}
	unit := systemdUnit(id)
	timerPath := filepath.Join(b.dir, unit+".timer")
	if _, err := os.Stat(timerPath); os.IsNotExist(err) {
		return nil
	}
	_, _ = b.run(ctx, "systemctl", []string{"disable", "--now", unit + ".timer"}, nil)
	for _, p := range []string{timerPath, filepath.Join(b.dir, unit+".service")} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	_, _ = b.run(ctx, "systemctl", []string{"daemon-reload"}, nil)
	return nil
}
