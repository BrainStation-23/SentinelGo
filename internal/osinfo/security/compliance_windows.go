package security

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"

	"sentinelgo/internal/osinfo/shared"
)

// applyCompliance fills the compliance telemetry keys (#172). updates is the
// Windows Update search collectSecurity already ran.
func applyCompliance(info *shared.SecurityInfo, updates missingUpdatesResult) {
	probe, _ := parseWinComplianceProbe(runWinComplianceProbe())

	info.ScreenLock = collectWindowsScreenLock()
	info.PasswordPolicy = collectWindowsPasswordPolicy()
	info.AutoLoginEnabled = collectWindowsAutoLogin()
	info.GuestAccountEnabled = probe.GuestEnabled
	info.RemoteAccess = collectWindowsRemoteAccess(probe.SMB1)
	info.Patching = collectWindowsPatching(probe.LastUpdate, updates)
	info.AuditLogging = collectWindowsAuditLogging()
	info.TimeSync = collectWindowsTimeSync()
	info.Backup = collectWindowsBackup()
}

// winComplianceScript reads the values that have no registry source in one
// PowerShell start: the built-in Guest account (RID 501, found by SID
// because it can be renamed), SMB1 server support, and when the last OS
// update was installed. Get-HotFix lists OS updates (with day precision);
// Windows Update history, without windowsNonPatchKBs, is the fallback.
// Each read is wrapped in try so one failure leaves only its own key out.
var winComplianceScript = strings.Join([]string{
	`$r = @{}`,
	`try { $g = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like '*-501' } | Select-Object -First 1; if ($g) { $r.GuestEnabled = [bool]$g.Enabled } } catch {}`,
	`try { $r.SMB1 = [bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch {}`,
	`try { $h = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1; if ($h) { $r.LastUpdate = ([DateTimeOffset]$h.InstalledOn).ToUnixTimeSeconds() } } catch {}`,
	`if (-not $r.ContainsKey('LastUpdate')) { try { $s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher(); $n = $s.GetTotalHistoryCount(); if ($n -gt 0) { $e = $s.QueryHistory(0, [Math]::Min($n, 200)) | Where-Object { $_.Operation -eq 1 -and $_.ResultCode -eq 2 -and $_.Title -notmatch '` + windowsNonPatchKBs + `' } | Sort-Object Date -Descending | Select-Object -First 1; if ($e) { $r.LastUpdate = ([DateTimeOffset][DateTime]::SpecifyKind($e.Date, 'Utc')).ToUnixTimeSeconds() } } } catch {} }`,
	`$r | ConvertTo-Json -Compress`,
}, "; ")

func runWinComplianceProbe() string {
	out, err := shared.RunPowerShell(winComplianceScript)
	if err != nil {
		return ""
	}
	return out
}

// ── registry helpers ──────────────────────────────────────────────────────────

// regAccess reads the 64-bit view, so a 32-bit agent on 64-bit Windows isn't
// redirected to WOW6432Node.
const regAccess = registry.QUERY_VALUE | registry.ENUMERATE_SUB_KEYS | registry.WOW64_64KEY

// regInt returns a registry value as an int: a DWORD/QWORD directly, or a
// string holding a number (the screen saver values are REG_SZ). -1 when the
// key or value is missing or isn't a number.
func regInt(root registry.Key, path, name string) int {
	k, err := registry.OpenKey(root, path, regAccess)
	if err != nil {
		return -1
	}
	defer func() { _ = k.Close() }()
	if v, _, err := k.GetIntegerValue(name); err == nil {
		if v > 1<<31 {
			return -1
		}
		return int(v)
	}
	if s, _, err := k.GetStringValue(name); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
			return n
		}
	}
	return -1
}

// regString returns a string value; ok is false when the key or value is
// missing.
func regString(root registry.Key, path, name string) (string, bool) {
	k, err := registry.OpenKey(root, path, regAccess)
	if err != nil {
		return "", false
	}
	defer func() { _ = k.Close() }()
	s, _, err := k.GetStringValue(name)
	return s, err == nil
}

func regKeyExists(root registry.Key, path string) bool {
	k, err := registry.OpenKey(root, path, regAccess)
	if err != nil {
		return false
	}
	_ = k.Close()
	return true
}

// serviceStart is a service's start type (2 auto, 3 manual, 4 disabled), or
// -1 when the service isn't installed.
func serviceStart(name string) int {
	return regInt(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+name, "Start")
}

// ── probes ────────────────────────────────────────────────────────────────────

// collectWindowsScreenLock reads the machine inactivity limit and the screen
// saver settings of every signed-in user. The agent runs as LocalSystem, so
// the users' settings are read from their loaded hives under HKEY_USERS.
func collectWindowsScreenLock() *shared.ScreenLockInfo {
	machine := regInt(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "InactivityTimeoutSecs")

	var users []winSaverSettings
	for _, sid := range signedInUserSIDs() {
		users = append(users, readSaverSettings(sid))
	}
	return windowsScreenLock(machine, users)
}

// signedInUserSIDs lists the loaded hives of real user accounts: local and
// domain (S-1-5-21-) and Entra ID (S-1-12-1-), skipping the _Classes hives.
func signedInUserSIDs() []string {
	k, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer func() { _ = k.Close() }()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}
	var sids []string
	for _, n := range names {
		if (strings.HasPrefix(n, "S-1-5-21-") || strings.HasPrefix(n, "S-1-12-1-")) && !strings.HasSuffix(n, "_Classes") {
			sids = append(sids, n)
		}
	}
	return sids
}

// readSaverSettings reads one user's screen saver settings; the user's Group
// Policy key wins over Control Panel. A screen saver only runs when one is
// chosen (SCRNSAVE.EXE): Windows leaves ScreenSaveActive=1 with "(None)".
func readSaverSettings(sid string) winSaverSettings {
	policy := sid + `\Software\Policies\Microsoft\Windows\Control Panel\Desktop`
	desktop := sid + `\Control Panel\Desktop`
	get := func(name string) int {
		return firstSet(regInt(registry.USERS, policy, name), regInt(registry.USERS, desktop, name))
	}
	exe, ok := regString(registry.USERS, policy, "SCRNSAVE.EXE")
	if !ok {
		exe, _ = regString(registry.USERS, desktop, "SCRNSAVE.EXE")
	}
	return winSaverSettings{
		Active:         get("ScreenSaveActive") == 1 && strings.TrimSpace(exe) != "",
		Secure:         get("ScreenSaverIsSecure") == 1,
		TimeoutSeconds: get("ScreenSaveTimeOut"),
	}
}

// collectWindowsPasswordPolicy exports the effective (domain + local)
// security policy with secedit and reads its [System Access] section.
func collectWindowsPasswordPolicy() *shared.PasswordPolicyInfo {
	dir, err := os.MkdirTemp("", "sentinelgo-secedit-")
	if err != nil {
		return nil
	}
	defer func() { _ = os.RemoveAll(dir) }()
	cfg := filepath.Join(dir, "policy.inf")
	if _, err := shared.RunCommand("secedit", "/export", "/mergedpolicy", "/areas", "SECURITYPOLICY", "/cfg", cfg, "/quiet"); err != nil {
		return nil
	}
	data, err := os.ReadFile(cfg) // #nosec G304 -- path is our own temp file
	if err != nil {
		return nil
	}
	return parseSeceditPasswordPolicy(decodeText(data))
}

func collectWindowsAutoLogin() *bool {
	const winlogon = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	if !regKeyExists(registry.LOCAL_MACHINE, winlogon) {
		return nil
	}
	v, _ := regString(registry.LOCAL_MACHINE, winlogon, "AutoAdminLogon")
	return shared.Bool(strings.TrimSpace(v) == "1")
}

// collectWindowsRemoteAccess reports RDP (and whether it requires Network
// Level Authentication), SMB1 and the OpenSSH server. smb1 comes from
// Get-SmbServerConfiguration; the LanmanServer registry switch is the
// fallback.
func collectWindowsRemoteAccess(smb1 *bool) *shared.RemoteAccessInfo {
	const (
		tsPolicy = `SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`
		ts       = `SYSTEM\CurrentControlSet\Control\Terminal Server`
		rdpTCP   = `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`
	)
	var r shared.RemoteAccessInfo
	r.RDPEnabled, r.RDPNLARequired = windowsRDP(
		regInt(registry.LOCAL_MACHINE, tsPolicy, "fDenyTSConnections"),
		regInt(registry.LOCAL_MACHINE, ts, "fDenyTSConnections"),
		regInt(registry.LOCAL_MACHINE, tsPolicy, "UserAuthentication"),
		regInt(registry.LOCAL_MACHINE, rdpTCP, "UserAuthentication"))

	r.SMB1Enabled = smb1
	if r.SMB1Enabled == nil {
		if v := regInt(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "SMB1"); v >= 0 {
			r.SMB1Enabled = shared.Bool(v != 0)
		}
	}

	exists, status, _ := queryServiceStatus("sshd")
	r.SSHEnabled = shared.Bool(exists && status == "Running")
	return nonZero(r)
}

func collectWindowsPatching(lastUpdate *int64, updates missingUpdatesResult) *shared.PatchingInfo {
	const (
		rebootRequired = `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`
		rebootPending  = `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`
		auPolicy       = `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`
	)
	p := shared.PatchingInfo{
		LastUpdateInstalledAt: unixISOTime(lastUpdate),
		PendingReboot: shared.Bool(regKeyExists(registry.LOCAL_MACHINE, rebootRequired) ||
			regKeyExists(registry.LOCAL_MACHINE, rebootPending)),
		AutoUpdateEnabled: shared.Bool(windowsAutoUpdate(
			regInt(registry.LOCAL_MACHINE, auPolicy, "NoAutoUpdate"),
			regInt(registry.LOCAL_MACHINE, auPolicy, "AUOptions"),
			serviceStart("wuauserv"))),
	}
	if updates.ok {
		missing := updates.updates
		p.MissingUpdates = &missing
	}
	return &p
}

// collectWindowsAuditLogging reads the audit policy via `auditpol /backup`
// (see parseAuditpolBackup) and the Security event log's maximum size.
func collectWindowsAuditLogging() *shared.AuditLoggingInfo {
	var a shared.AuditLoggingInfo
	if enabled, categories, ok := readAuditpolBackup(); ok {
		a.Enabled = shared.Bool(enabled)
		a.Categories = categories
	}
	a.LogMaxSizeMB = windowsEventLogMB(
		regInt(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\EventLog\Security`, "MaxSize"),
		regInt(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\EventLog\Security`, "MaxSize"))
	if a.Enabled == nil && a.LogMaxSizeMB == nil {
		return nil
	}
	return &a
}

func readAuditpolBackup() (enabled bool, categories []string, ok bool) {
	dir, err := os.MkdirTemp("", "sentinelgo-auditpol-")
	if err != nil {
		return false, nil, false
	}
	defer func() { _ = os.RemoveAll(dir) }()
	file := filepath.Join(dir, "audit.csv")
	if _, err := shared.RunCommand("auditpol", "/backup", "/file:"+file); err != nil {
		return false, nil, false
	}
	data, err := os.ReadFile(file) // #nosec G304 -- path is our own temp file
	if err != nil {
		return false, nil, false
	}
	return parseAuditpolBackup(decodeText(data))
}

func collectWindowsTimeSync() *shared.TimeSyncInfo {
	const params = `SYSTEM\CurrentControlSet\Services\W32Time\Parameters`
	syncType, _ := regString(registry.LOCAL_MACHINE, params, "Type")
	server, _ := regString(registry.LOCAL_MACHINE, params, "NtpServer")
	return windowsTimeSync(syncType, server, serviceStart("W32Time"))
}

// windowsBackupServices are the services of common Windows backup agents.
var windowsBackupServices = []struct {
	service string
	product string
}{
	{"VeeamEndpointBackupSvc", "Veeam Agent"},
	{"bzserv", "Backblaze"},
	{"CarboniteService", "Carbonite"},
	{"Code42Service", "Code42"},
	{"CrashPlanService", "CrashPlan"},
	{"inSyncCPHService", "Druva inSync"},
}

// collectWindowsBackup reports the first known backup agent installed; it is
// enabled unless its service is disabled. With none found the key is left
// out: an unrecognised product may still be backing the machine up.
func collectWindowsBackup() *shared.BackupInfo {
	for _, b := range windowsBackupServices {
		if start := serviceStart(b.service); start >= 0 {
			return &shared.BackupInfo{Product: b.product, Enabled: shared.Bool(start != 4)}
		}
	}
	return nil
}
