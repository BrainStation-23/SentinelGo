package updater

// Boot-time watchdog (#516).
//
// The watchdog that startHealthWatch spawns is a plain process and doesn't
// survive a reboot. Until #516 only the new binary brought one back
// (StartHealthCheck -> ensureWatchdog), so an update that crashed before
// StartHealthCheck after a reboot was never rolled back. While an update is
// pending, a boot job now starts the watchdog copy (never the new binary)
// with --boot:
//
//   - Linux: a systemd unit enabled for multi-user.target;
//   - macOS: a LaunchDaemon with RunAtLoad;
//   - Windows: a scheduled task with a boot trigger, running as SYSTEM.
//
// The job is registered with the marker (startHealthWatch, and again by the
// new binary at each start, so an update from a release without #516 is
// covered from its first start), and removed as soon as no update is pending
// any more: by the watchdog when it exits, by endHealthWatch, by the agent
// confirming the update healthy, and by the update checks retiring a stale
// marker. The watchdog lock keeps a boot-started watchdog and one the new
// binary starts from running together.

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"unicode/utf16"
)

// BootWatchdogFlag marks a watchdog started at boot (`update-watchdog
// --marker <path> --boot`).
const BootWatchdogFlag = "--boot"

// Boot job names.
const (
	bootUnitName  = "sentinelgo-update-watchdog.service"
	bootLabel     = "com.sentinelgo.update-watchdog"
	bootTaskName  = `SentinelGo\UpdateWatchdog`
	bootUnitDescr = "SentinelGo update watchdog: rolls back a self-update that fails after a reboot"
)

// Registration, swapped in tests.
var (
	registerBootWatchdogFn   = registerBootWatchdog
	unregisterBootWatchdogFn = unregisterBootWatchdog
)

// errBootUnsupported: this OS has no boot job mechanism we use (e.g. Linux
// without systemd). The running watchdog still covers an update without a
// reboot.
var errBootUnsupported = errors.New("no boot job support on this system")

// registerBoot registers the boot job, logging (not failing) on error: the
// spawned watchdog already covers an update that isn't interrupted by a
// reboot.
func registerBoot(m *Marker, markerPath string) {
	if err := registerBootWatchdogFn(m, markerPath); err != nil {
		if errors.Is(err, errBootUnsupported) {
			log.Printf("Updater: no boot-time update watchdog on this system: %v", err)
			return
		}
		log.Printf("Updater: can't register the boot-time update watchdog (a reboot during the health check would leave the update unwatched): %v", err)
	}
}

// unregisterBoot removes the boot job, logging on error.
func unregisterBoot() {
	if err := unregisterBootWatchdogFn(); err != nil && !errors.Is(err, errBootUnsupported) {
		log.Printf("Updater: can't remove the boot-time update watchdog: %v", err)
	}
}

// updatePending reports whether markerPath still describes an update a
// watchdog could roll back: a valid marker whose backup exists. A marker kept
// only as the record of a rolled-back version (its backup is gone) isn't one.
func updatePending(markerPath string) bool {
	m, err := ReadMarker(markerPath)
	if err != nil || m.validate() != nil {
		return false
	}
	_, err = os.Stat(m.BackupPath)
	return err == nil
}

// retireBootIfDone removes the boot job unless an update is still pending
// (e.g. a rollback whose install failed keeps its marker and backup, so the
// next boot tries again).
func retireBootIfDone(markerPath string) {
	if !updatePending(markerPath) {
		unregisterBoot()
	}
}

// bootArgs is the watchdog command line after the program.
func bootArgs(markerPath string) []string {
	return []string{UpdateWatchdogCommand, "--marker", markerPath, BootWatchdogFlag}
}

// checkBootPaths rejects paths that would need escaping in a systemd unit or
// a scheduled task's command line. The agent's own paths never do.
func checkBootPaths(paths ...string) error {
	for _, p := range paths {
		if p == "" || strings.ContainsAny(p, "\"%\r\n\x00") {
			return fmt.Errorf("unsupported path for the boot job: %q", p)
		}
	}
	return nil
}

// systemdUnit is the Linux boot job. Type=simple: the watchdog runs until
// the update ends. ConditionPathExists skips it when the marker is gone.
func systemdUnit(m *Marker, markerPath string) (string, error) {
	if err := checkBootPaths(m.WatchdogPath, markerPath); err != nil {
		return "", err
	}
	args := bootArgs(markerPath)
	return fmt.Sprintf(`[Unit]
Description=%s
Wants=network-online.target
After=network-online.target
ConditionPathExists=%s

[Service]
Type=simple
ExecStart="%s" %s --marker "%s" %s
Restart=no

[Install]
WantedBy=multi-user.target
`, bootUnitDescr, markerPath, m.WatchdogPath, args[0], args[2], args[3]), nil
}

// xmlText escapes s for XML character data.
func xmlText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// launchdBootPlist is the macOS boot job: loaded by launchd at every boot
// while the file exists. KeepAlive false: the watchdog exits for good.
func launchdBootPlist(m *Marker, markerPath string) (string, error) {
	if err := checkBootPaths(m.WatchdogPath, markerPath); err != nil {
		return "", err
	}
	var args strings.Builder
	for _, a := range append([]string{m.WatchdogPath}, bootArgs(markerPath)...) {
		fmt.Fprintf(&args, "        <string>%s</string>\n", xmlText(a))
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
%s    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>UserName</key>
    <string>root</string>
</dict>
</plist>
`, bootLabel, args.String()), nil
}

// scheduledTaskXML is the Windows boot job: a boot trigger, SYSTEM (S-1-5-18),
// allowed on battery, and a 2-day limit (the watchdog waits up to GiveUpAt).
// Returned as UTF-16LE with a BOM, which schtasks /XML expects.
func scheduledTaskXML(m *Marker, markerPath string) ([]byte, error) {
	if err := checkBootPaths(m.WatchdogPath, markerPath); err != nil {
		return nil, err
	}
	args := bootArgs(markerPath)
	cmdArgs := fmt.Sprintf(`%s --marker "%s" %s`, args[0], args[2], args[3])
	s := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>%s</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="System">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>P2D</ExecutionTimeLimit>
  </Settings>
  <Actions Context="System">
    <Exec>
      <Command>%s</Command>
      <Arguments>%s</Arguments>
    </Exec>
  </Actions>
</Task>
`, xmlText(bootUnitDescr), xmlText(m.WatchdogPath), xmlText(cmdArgs))
	u := utf16.Encode([]rune(s))
	out := make([]byte, 2, 2+2*len(u))
	out[0], out[1] = 0xff, 0xfe // UTF-16LE BOM
	for _, c := range u {
		out = binary.LittleEndian.AppendUint16(out, c)
	}
	return out, nil
}
