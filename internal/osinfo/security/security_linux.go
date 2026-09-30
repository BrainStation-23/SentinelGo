package security

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// crowdStrikeFalconService and crowdStrikeFalconName identify CrowdStrike
// Falcon, which appears in both the AV-service and EDR-detection tables below.
const (
	crowdStrikeFalconService = "falcon-sensor"
	crowdStrikeFalconName    = "CrowdStrike Falcon"
)

// knownAVServices lists systemd service names for common endpoint-protection products.
var knownAVServices = []struct {
	service string
	name    string
}{
	{"clamav-daemon", "ClamAV"},
	{"clamd", "ClamAV"},
	{crowdStrikeFalconService, crowdStrikeFalconName},
	{"falcond", crowdStrikeFalconName},
	{"cbsensor", "Carbon Black"},
	{"ds_agent", "Trend Micro Deep Security"},
	{"sophos-spl", "Sophos"},
	{"sav-protect", "Sophos AV"},
	{"symantec_antivirus", "Symantec Antivirus"},
	{"eset-daemon", "ESET"},
}

func collectSecurity() shared.SecurityInfo {
	profiles := collectFirewallProfiles()
	fwEnabled := anyFirewallEnabled(profiles)

	avProducts := collectAV()
	coreIsolation := collectCoreIsolation()
	secureBoot := collectSecureBoot()
	ports := collectListeningPorts()
	usb := collectUSBMassStorage()

	fwSec := collectFirewallSecurity(profiles)
	avProtection := buildAVProtection(avProducts)

	edrXdr := collectEDRInfo()
	kernelHard := shared.KernelHardeningInfo{
		MemoryIntegrityEnabled: false,
		VBSEnabled:             false,
		SELinuxMode:            coreIsolation.SELinuxMode,
		AppArmorEnabled:        coreIsolation.AppArmorEnabled,
		KernelLockdown:         coreIsolation.KernelLockdown,
		USBMassStorageEnabled:  usb,
	}
	devEnc := collectDeviceEncryption()
	hwSec := collectHardwareSecurity()
	idAccess := collectIdentityAccessControl()
	netExposure := collectNetworkExposure(ports, idAccess)

	posture := generatePostureSummary(fwSec, avProtection, edrXdr, devEnc, hwSec, idAccess, netExposure)

	return shared.SecurityInfo{
		AntivirusProducts:     avProducts,
		FirewallEnabled:       fwEnabled,
		FirewallProfiles:      profiles,
		CoreIsolation:         coreIsolation,
		SecureBootEnabled:     secureBoot,
		ListeningPorts:        ports,
		USBMassStorageEnabled: usb,

		FirewallSecurity:      fwSec,
		AntivirusProtection:   avProtection,
		EDRXDRDetection:       edrXdr,
		KernelHardening:       kernelHard,
		DeviceEncryption:      devEnc,
		HardwareSecurity:      hwSec,
		IdentityAccessControl: idAccess,
		NetworkExposureAccess: netExposure,
		PostureSummary:        posture,
	}
}

// anyFirewallEnabled reports whether at least one firewall profile is enabled.
func anyFirewallEnabled(profiles []shared.FirewallProfile) bool {
	for _, p := range profiles {
		if p.Enabled {
			return true
		}
	}
	return false
}

// buildAVProtection converts detected AV products into the AntivirusProtection
// summary, attaching ClamAV scan details when the product is ClamAV.
func buildAVProtection(avProducts []shared.AntivirusProduct) shared.AntivirusProtectionInfo {
	var avProtection shared.AntivirusProtectionInfo
	for _, av := range avProducts {
		details := shared.AntivirusDetails{
			ProductName:             av.Name,
			Vendor:                  "Unknown",
			Version:                 "Unknown",
			RealTimeProtectionState: "Unknown",
			ServiceStatus:           "Unknown",
			UpdateStatus:            "Unknown",
		}
		applyAVEnabledState(&details, av.Enabled)

		if strings.Contains(strings.ToLower(av.Name), "clamav") {
			scan := collectClamAVScanInfo()
			details.ScanInfo = &scan
		}
		avProtection.Products = append(avProtection.Products, details)
	}
	return avProtection
}

// applyAVEnabledState maps the raw "enabled"/"disabled" AV state string onto
// the RealTimeProtectionState and ServiceStatus fields.
func applyAVEnabledState(details *shared.AntivirusDetails, enabledStr string) {
	if strings.EqualFold(enabledStr, "enabled") {
		details.RealTimeProtectionState = "Enabled"
		details.ServiceStatus = "Running"
	} else if strings.EqualFold(enabledStr, "disabled") {
		details.RealTimeProtectionState = "Disabled"
		details.ServiceStatus = "Stopped"
	}
}

// collectClamAVScanInfo reads the ClamAV log for the most recent scan summary
// time, scanned-file count, and any infected-file detections.
func collectClamAVScanInfo() shared.SecurityScanInfo {
	var scan shared.SecurityScanInfo
	scan.LastScanTime = "Unknown"
	scan.ScanType = "Scheduled/On-Demand"
	scan.ScanResult = "Clean"

	logData, err := os.ReadFile("/var/log/clamav/clamav.log")
	if err != nil {
		return scan
	}
	lines := strings.Split(string(logData), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		parseClamAVLogLine(strings.TrimSpace(lines[i]), &scan)
	}
	return scan
}

// parseClamAVLogLine inspects a single ClamAV log line, updating scan with
// the scan summary time, scanned-file count, and infected-file details.
func parseClamAVLogLine(line string, scan *shared.SecurityScanInfo) {
	if strings.Contains(line, "SCAN SUMMARY") && len(line) > 24 {
		scan.LastScanTime = line[:20]
	}
	if strings.Contains(line, "Scanned files:") {
		if count, ok := parseClamAVCount(line); ok {
			scan.ScannedFilesCount = int64(count)
		}
	}
	if strings.Contains(line, "Infected files:") {
		if count, ok := parseClamAVCount(line); ok && count > 0 {
			scan.ScanResult = "Threats Detected"
			scan.RecentThreats = append(scan.RecentThreats, shared.ThreatDetails{
				ThreatName:    "Infected File",
				Severity:      "High",
				FilePath:      "Check /var/log/clamav/clamav.log",
				ActionTaken:   "Detected",
				DetectionTime: scan.LastScanTime,
			})
		}
	}
}

// parseClamAVCount extracts the integer count from a "Label: N" style ClamAV
// log line.
func parseClamAVCount(line string) (int, bool) {
	parts := strings.Split(line, ":")
	if len(parts) < 2 {
		return 0, false
	}
	var count int
	if _, err := fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &count); err != nil {
		return 0, false
	}
	return count, true
}

// edrCandidate describes a known EDR/XDR product to probe for on Linux: its
// systemd service name, the process name to look for as a fallback, and the
// human-facing product/vendor names.
type edrCandidate struct {
	svc    string
	name   string
	vendor string
	proc   string
}

func collectEDRInfo() shared.EDRXDRDetectionInfo {
	var info shared.EDRXDRDetectionInfo
	knownEDR := []edrCandidate{
		{crowdStrikeFalconService, crowdStrikeFalconName, "CrowdStrike", crowdStrikeFalconService},
		{"sentinelone", "SentinelOne Singularity", "SentinelOne", "sentineld"},
		{"wazuh-agent", "Wazuh Agent", "Wazuh", "wazuh-agentd"},
		{"velociraptor", "Velociraptor", "Velociraptor", "velociraptor"},
		{"osqueryd", "Osquery", "Osquery", "osqueryd"},
	}

	runningProcs := runningProcNames()

	for _, e := range knownEDR {
		installed, status, startup := detectEDRServiceState(e, runningProcs)
		if !installed {
			continue
		}
		info.Agents = append(info.Agents, buildEDRAgent(e, status, startup))
	}
	return info
}

// runningProcNames returns the set of process comm names currently running,
// read from /proc/<pid>/comm.
func runningProcNames() map[string]bool {
	running := make(map[string]bool)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return running
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err != nil {
			continue
		}
		comm, err := os.ReadFile("/proc/" + e.Name() + "/comm")
		if err != nil {
			continue
		}
		running[strings.TrimSpace(string(comm))] = true
	}
	return running
}

// detectEDRServiceState probes systemctl (and, as a fallback, the running
// process table) to determine whether an EDR candidate is installed and its
// current service status/startup mode.
func detectEDRServiceState(e edrCandidate, runningProcs map[string]bool) (installed bool, status, startup string) {
	status = "Stopped"
	startup = "Disabled"

	if activeOut, err := shared.RunCommand("systemctl", "is-active", e.svc); err == nil {
		installed = true
		if strings.TrimSpace(activeOut) == "active" {
			status = "Running"
		}
	}
	if enabledOut, err := shared.RunCommand("systemctl", "is-enabled", e.svc); err == nil {
		installed = true
		if strings.TrimSpace(enabledOut) == "enabled" {
			startup = "Auto"
		}
	}

	if !installed && runningProcs[e.proc] {
		installed = true
		status = "Running"
		startup = "Manual"
	}

	return installed, status, startup
}

// buildEDRAgent constructs the agent details for an installed EDR candidate,
// deriving health from its service status.
func buildEDRAgent(e edrCandidate, status, startup string) shared.EDRXDRAgentDetails {
	agent := shared.EDRXDRAgentDetails{
		AgentName:              e.name,
		Vendor:                 e.vendor,
		AgentVersion:           "Unknown",
		ServiceStatus:          status,
		HealthStatus:           "Healthy",
		ConnectivityStatus:     "Unknown",
		TamperProtectionStatus: "Unknown",
		Installed:              true,
		Running:                status == "Running",
		Stopped:                status == "Stopped",
		Disabled:               startup == "Disabled",
	}

	if status == "Running" {
		agent.Healthy = true
	} else {
		agent.HealthStatus = "Unhealthy"
		agent.Unhealthy = true
		agent.Offline = true
	}

	return agent
}

func collectDeviceEncryption() shared.DeviceEncryptionInfo {
	var enc shared.DeviceEncryptionInfo
	enc.EncryptionProvider = "None"
	enc.EncryptionStatus = "Unencrypted"
	enc.ProtectionStatus = "Disabled"
	enc.RecoveryKeyBackupStatus = "Unknown"

	if output, err := shared.RunCommand("lsblk", "-o", "NAME,FSTYPE"); err == nil {
		if strings.Contains(output, "crypto_LUKS") {
			enc.EncryptionProvider = "LUKS"
			enc.EncryptionStatus = "Encrypted"
			enc.ProtectionStatus = "Enabled"
		}
	}
	return enc
}

func collectHardwareSecurity() shared.HardwareSecurityInfo {
	var hw shared.HardwareSecurityInfo
	hw.SecureBootStatus = collectSecureBoot()
	hw.TPMStatus = "Unsupported"
	hw.TPMVersion = "None"
	hw.SecureEnclaveStatus = "Unsupported"
	hw.ActivationLockStatus = "Unsupported"

	if _, err := os.Stat("/dev/tpm0"); err == nil {
		hw.TPMStatus = "Enabled"
		hw.TPMVersion = "1.2"

		if data, err := os.ReadFile("/sys/class/tpm/tpm0/tpm_version_major"); err == nil {
			hw.TPMVersion = strings.TrimSpace(string(data)) + ".0"
		} else if data, err = os.ReadFile("/sys/class/tpm/tpm0/device/description"); err == nil {
			if strings.Contains(string(data), "2.0") {
				hw.TPMVersion = "2.0"
			}
		}
	} else if _, err := os.Stat("/sys/class/tpm"); err == nil {
		hw.TPMStatus = "Disabled"
	}
	return hw
}

// parseSSHConfigData parses the contents of an sshd_config file and returns the
// PermitRootLogin, PasswordAuthentication, and PubkeyAuthentication settings.
// Commented-out lines are ignored; unknown values leave the field as "Unknown".
func parseSSHConfigData(data string) (rootLogin, passwordAuth, pubkeyAuth string) {
	rootLogin = "Unknown"
	passwordAuth = "Unknown"
	pubkeyAuth = "Unknown"
	for _, line := range strings.Split(data, "\n") {
		key, val, ok := parseSSHConfigLine(line)
		if !ok {
			continue
		}
		switch key {
		case "permitrootlogin":
			if s := sshYesNoState(val, "prohibit-password"); s != "" {
				rootLogin = s
			}
		case "passwordauthentication":
			if s := sshYesNoState(val); s != "" {
				passwordAuth = s
			}
		case "pubkeyauthentication":
			if s := sshYesNoState(val); s != "" {
				pubkeyAuth = s
			}
		}
	}
	return
}

// parseSSHConfigLine extracts a lower-cased key/value pair from a single
// sshd_config line. ok is false for comments and lines without a value.
func parseSSHConfigLine(line string) (key, val string, ok bool) {
	l := strings.TrimSpace(line)
	if strings.HasPrefix(l, "#") {
		return "", "", false
	}
	fields := strings.Fields(l)
	if len(fields) < 2 {
		return "", "", false
	}
	return strings.ToLower(fields[0]), strings.ToLower(fields[1]), true
}

// sshYesNoState maps a "yes"/"no" sshd_config value to "Enabled"/"Disabled".
// extraDisabled lists additional values (e.g. "prohibit-password") that also
// count as Disabled. Returns "" when val matches none of these, so the caller
// can leave the field at its existing default.
func sshYesNoState(val string, extraDisabled ...string) string {
	if val == "yes" {
		return "Enabled"
	}
	if val == "no" {
		return "Disabled"
	}
	for _, v := range extraDisabled {
		if val == v {
			return "Disabled"
		}
	}
	return ""
}

// countAptSecurityUpdates counts pending security updates from apt-get -s upgrade output.
// Only lines from a *-security pocket are counted (identified by the "-security" suffix).
func countAptSecurityUpdates(output string) int {
	count := 0
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "Inst ") && strings.Contains(strings.ToLower(line), "-security") {
			count++
		}
	}
	return count
}

// countYumSecurityUpdates counts pending security updates from yum check-update --security output.
// Package lines contain a "." (name.arch) or "-" (version separator).
func countYumSecurityUpdates(output string) int {
	count := 0
	for _, line := range strings.Split(output, "\n") {
		l := strings.ToLower(strings.TrimSpace(line))
		if l == "" || strings.HasPrefix(l, "loaded") || strings.HasPrefix(l, "last") {
			continue
		}
		if strings.Contains(l, "security") && (strings.Contains(line, ".") || strings.Contains(line, "-")) {
			count++
		}
	}
	return count
}

func collectIdentityAccessControl() shared.IdentityAccessControlInfo {
	var id shared.IdentityAccessControlInfo
	id.SSHRootLogin = "Unknown"
	id.SSHPasswordAuth = "Unknown"

	if data, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
		id.SSHRootLogin, id.SSHPasswordAuth, _ = parseSSHConfigData(string(data))
	}

	id.SudoPrivilege = detectSudoPrivilegeState()

	id.PatchComplianceStatus = "Compliant"
	id.PendingSecurityPatches = pendingSecurityPatchCount()
	if id.PendingSecurityPatches > 0 {
		id.PatchComplianceStatus = "Non-Compliant"
	}

	return id
}

// detectSudoPrivilegeState checks /etc/group for a sudo or wheel group,
// reporting whether sudo access is configured as expected.
func detectSudoPrivilegeState() string {
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return "Unknown"
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) >= 4 && (parts[0] == "sudo" || parts[0] == "wheel") {
			return "Configured"
		}
	}
	return "Misconfigured"
}

// pendingSecurityPatchCount queries the system's package manager for the
// number of pending security updates, trying apt-check, then apt-get, then
// yum in turn.
func pendingSecurityPatchCount() int {
	if _, err := os.Stat("/usr/lib/update-notifier/apt-check"); err == nil {
		return pendingPatchesFromAptCheck()
	}
	if _, err := os.Stat("/usr/bin/apt-get"); err == nil {
		return pendingPatchesFromAptGet()
	}
	if _, err := os.Stat("/usr/bin/yum"); err == nil {
		return pendingPatchesFromYum()
	}
	return 0
}

// pendingPatchesFromAptCheck parses the "N;M" output of apt-check, where M is
// the count of pending security updates.
func pendingPatchesFromAptCheck() int {
	out, err := shared.RunCommand("/usr/lib/update-notifier/apt-check")
	if err != nil {
		return 0
	}
	parts := strings.Split(strings.TrimSpace(out), ";")
	if len(parts) < 2 {
		return 0
	}
	var sec int
	if _, err := fmt.Sscanf(parts[1], "%d", &sec); err != nil {
		return 0
	}
	return sec
}

func pendingPatchesFromAptGet() int {
	out, err := shared.RunCommand("apt-get", "-s", "upgrade")
	if err != nil {
		return 0
	}
	return countAptSecurityUpdates(out)
}

// pendingPatchesFromYum runs yum check-update --security, which exits 100
// when updates are available and 0 when there are none; RunCommandOutput
// captures output for both exit codes.
func pendingPatchesFromYum() int {
	out, exitCode, err := shared.RunCommandOutput("yum", "check-update", "--security")
	if err != nil || (exitCode != 0 && exitCode != 100) {
		return 0
	}
	return countYumSecurityUpdates(out)
}

func collectNetworkExposure(ports []shared.ListeningPort, id shared.IdentityAccessControlInfo) shared.NetworkExposureAccessInfo {
	info := analyzeNetworkExposure(ports)

	info.SSHRootLoginStatus = id.SSHRootLogin
	info.SSHPasswordAuthStatus = id.SSHPasswordAuth

	info.SSHKeyAuthStatus = "Unknown"
	if data, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
		_, _, info.SSHKeyAuthStatus = parseSSHConfigData(string(data))
	}
	return info
}

// collectUSBMassStorage checks whether USB mass storage is active or explicitly
// blocked on Linux.
// If the usb_storage kernel module is loaded, a device is (or was recently)
// connected and mass storage is enabled. If the module is not loaded but is
// blacklisted in /etc/modprobe.d, it has been administratively disabled.
// "unknown" is returned when the module is absent but not explicitly blocked —
// this is normal when no USB drive is connected on an otherwise unrestricted system.
func collectUSBMassStorage() string {
	if _, err := os.Stat("/sys/module/usb_storage"); err == nil {
		return "enabled"
	}
	if state := usbStorageStateFromModprobeDir("/etc/modprobe.d"); state != "" {
		return state
	}
	return "unknown"
}

// usbStorageStateFromModprobeDir scans *.conf files in dir for a blacklist or
// install-to-/bin/false directive that disables the usb_storage module.
// Returns "disabled" when found, "" otherwise (including when dir is unreadable).
func usbStorageStateFromModprobeDir(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		if state := usbStorageStateFromConfFile(filepath.Join(dir, e.Name())); state != "" {
			return state
		}
	}
	return ""
}

// usbStorageStateFromConfFile checks a single modprobe.d conf file for directives
// that disable usb_storage. Returns "disabled" when found, "" otherwise.
func usbStorageStateFromConfFile(path string) string {
	data, err := os.ReadFile(path) // #nosec G304 — path comes from os.ReadDir, not user input
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(strings.ToLower(line))
		if strings.HasPrefix(l, "blacklist") && strings.Contains(l, "usb_storage") {
			return "disabled"
		}
		if strings.HasPrefix(l, "install usb_storage") && strings.Contains(l, "/bin/false") {
			return "disabled"
		}
	}
	return ""
}

// collectAV probes systemctl for known AV daemons.
func collectAV() []shared.AntivirusProduct {
	var products []shared.AntivirusProduct
	seen := map[string]bool{}
	for _, svc := range knownAVServices {
		if seen[svc.name] {
			continue
		}
		if p, ok := probeAVService(svc.service, svc.name); ok {
			seen[svc.name] = true
			products = append(products, p)
		}
	}
	return products
}

func probeAVService(service, name string) (shared.AntivirusProduct, bool) {
	output, err := shared.RunCommand("systemctl", "is-active", service)
	if err != nil {
		return shared.AntivirusProduct{}, false
	}
	state := strings.TrimSpace(output)
	if state != "active" && state != "inactive" {
		return shared.AntivirusProduct{}, false
	}
	avEnabled := "disabled"
	if state == "active" {
		avEnabled = "enabled"
	}
	return shared.AntivirusProduct{
		Name:     name,
		Enabled:  avEnabled,
		UpToDate: "unknown",
		Source:   "service",
	}, true
}

// collectFirewallProfiles tries ufw, then firewalld, then iptables.
func collectFirewallProfiles() []shared.FirewallProfile {
	if output, err := shared.RunCommand("ufw", "status"); err == nil {
		// First line is "Status: active" or "Status: inactive".
		first := strings.ToLower(strings.SplitN(output, "\n", 2)[0])
		active := strings.Contains(first, "active") && !strings.Contains(first, "inactive")
		return []shared.FirewallProfile{{Name: "ufw", Enabled: active}}
	}
	if output, err := shared.RunCommand("firewall-cmd", "--state"); err == nil {
		running := strings.TrimSpace(strings.ToLower(output)) == "running"
		return []shared.FirewallProfile{{Name: "firewalld", Enabled: running}}
	}
	// iptables is a last resort: report enabled only when DROP/REJECT rules exist.
	// An empty ACCEPT-all ruleset is not a meaningful firewall.
	if output, err := shared.RunCommand("iptables", "-L", "-n"); err == nil {
		lower := strings.ToLower(output)
		hasRules := strings.Contains(lower, "drop") || strings.Contains(lower, "reject")
		return []shared.FirewallProfile{{Name: "iptables", Enabled: hasRules}}
	}
	return nil
}

func collectCoreIsolation() shared.CoreIsolationInfo {
	return shared.CoreIsolationInfo{
		SELinuxMode:     collectSELinux(),
		AppArmorEnabled: collectAppArmor(),
		KernelLockdown:  collectKernelLockdown(),
	}
}

// collectSELinux reads the SELinux enforcement mode from sysfs or sestatus.
func collectSELinux() string {
	if data, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		switch strings.TrimSpace(string(data)) {
		case "1":
			return "enforcing"
		case "0":
			return "permissive"
		}
	}
	if output, err := shared.RunCommand("sestatus"); err == nil {
		if mode := parseSEStatusOutput(output); mode != "" {
			return mode
		}
	}
	return "unknown"
}

// parseSEStatusOutput extracts the SELinux mode from sestatus output.
func parseSEStatusOutput(output string) string {
	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "selinux status:") && strings.Contains(lower, "disabled") {
			return "disabled"
		}
		if strings.HasPrefix(lower, "current mode:") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				mode := strings.ToLower(parts[len(parts)-1])
				if mode == "enforcing" || mode == "permissive" {
					return mode
				}
			}
		}
	}
	return ""
}

// collectAppArmor returns true when AppArmor is loaded.
func collectAppArmor() bool {
	if _, err := os.Stat("/sys/kernel/security/apparmor"); err == nil {
		return true
	}
	_, err := shared.RunCommand("aa-status", "--enabled")
	return err == nil
}

// collectKernelLockdown reads the active kernel lockdown mode from sysfs.
// The active mode is enclosed in brackets: "none [integrity] confidentiality"
func collectKernelLockdown() string {
	data, err := os.ReadFile("/sys/kernel/security/lockdown")
	if err != nil {
		return "unknown"
	}
	content := string(data)
	for _, mode := range []string{"confidentiality", "integrity", "none"} {
		if strings.Contains(content, "["+mode+"]") {
			return mode
		}
	}
	return "unknown"
}

// collectSecureBoot checks UEFI Secure Boot state via mokutil or EFI variables.
func collectSecureBoot() string {
	if output, err := shared.RunCommand("mokutil", "--sb-state"); err == nil {
		lower := strings.ToLower(strings.TrimSpace(output))
		if strings.Contains(lower, "secureboot enabled") {
			return "enabled"
		}
		if strings.Contains(lower, "secureboot disabled") {
			return "disabled"
		}
	}
	return secureBootFromEFIVars("/sys/firmware/efi/efivars")
}

// secureBootFromEFIVars reads the SecureBoot EFI variable from efivarsDir.
// The variable is 5 bytes: 4-byte attribute header + 1 value byte (1=enabled, 0=disabled).
func secureBootFromEFIVars(efivarsDir string) string {
	entries, err := os.ReadDir(efivarsDir)
	if err != nil {
		return "unknown"
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "SecureBoot-") {
			data, rerr := os.ReadFile(filepath.Join(efivarsDir, e.Name()))
			if rerr == nil && len(data) >= 5 {
				if data[4] == 1 {
					return "enabled"
				}
				return "disabled"
			}
			break
		}
	}
	return "unknown"
}
