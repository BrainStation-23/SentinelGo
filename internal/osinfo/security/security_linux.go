package security

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// knownAVServices lists systemd service names for common endpoint-protection products.
var knownAVServices = []struct {
	service string
	name    string
}{
	{"clamav-daemon", "ClamAV"},
	{"clamd", "ClamAV"},
	{"falcon-sensor", "CrowdStrike Falcon"},
	{"falcond", "CrowdStrike Falcon"},
	{"cbsensor", "Carbon Black"},
	{"ds_agent", "Trend Micro Deep Security"},
	{"sophos-spl", "Sophos"},
	{"sav-protect", "Sophos AV"},
	{"symantec_antivirus", "Symantec Antivirus"},
	{"eset-daemon", "ESET"},
}

func collectSecurity() shared.SecurityInfo {
	profiles := collectFirewallProfiles()
	fwEnabled := false
	for _, p := range profiles {
		if p.Enabled {
			fwEnabled = true
			break
		}
	}
	
	avProducts := collectAV()
	coreIsolation := collectCoreIsolation()
	secureBoot := collectSecureBoot()
	ports := collectListeningPorts()
	usb := collectUSBMassStorage()

	fwSec := collectFirewallSecurity(profiles)
	
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
		if strings.EqualFold(av.Enabled, "enabled") {
			details.RealTimeProtectionState = "Enabled"
			details.ServiceStatus = "Running"
		} else if strings.EqualFold(av.Enabled, "disabled") {
			details.RealTimeProtectionState = "Disabled"
			details.ServiceStatus = "Stopped"
		}
		
		if strings.Contains(strings.ToLower(av.Name), "clamav") {
			var scan shared.SecurityScanInfo
			scan.LastScanTime = "Unknown"
			scan.ScanType = "Scheduled/On-Demand"
			scan.ScanResult = "Clean"
			
			if logData, err := os.ReadFile("/var/log/clamav/clamav.log"); err == nil {
				lines := strings.Split(string(logData), "\n")
				for i := len(lines) - 1; i >= 0; i-- {
					line := strings.TrimSpace(lines[i])
					if strings.Contains(line, "SCAN SUMMARY") {
						if len(line) > 24 {
							scan.LastScanTime = line[:20]
						}
					}
					if strings.Contains(line, "Infected files:") {
						parts := strings.Split(line, ":")
						if len(parts) >= 2 {
							var infectedCount int
							fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &infectedCount)
							scan.ScannedFilesCount = int64(infectedCount)
							if infectedCount > 0 {
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
				}
			}
			details.ScanInfo = &scan
		}
		avProtection.Products = append(avProtection.Products, details)
	}

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
	netExposure := collectNetworkExposure(ports)
	
	posture := generatePostureSummary(fwSec, avProtection, edrXdr, devEnc, hwSec, idAccess, netExposure)

	return shared.SecurityInfo{
		AntivirusProducts:     avProducts,
		FirewallEnabled:       fwEnabled,
		FirewallProfiles:      profiles,
		CoreIsolation:         coreIsolation,
		SecureBootEnabled:     secureBoot,
		ListeningPorts:        ports,
		USBMassStorageEnabled: usb,

		FirewallSecurity:       fwSec,
		AntivirusProtection:    avProtection,
		EDRXDRDetection:        edrXdr,
		KernelHardening:        kernelHard,
		DeviceEncryption:       devEnc,
		HardwareSecurity:       hwSec,
		IdentityAccessControl:  idAccess,
		NetworkExposureAccess:  netExposure,
		PostureSummary:         posture,
	}
}

func collectFirewallSecurity(profiles []shared.FirewallProfile) shared.FirewallSecurityInfo {
	var f shared.FirewallSecurityInfo
	f.Profiles = profiles
	allEnabled := true
	anyEnabled := false
	for _, p := range profiles {
		f.ActiveProfiles = append(f.ActiveProfiles, p.Name)
		if p.Enabled {
			anyEnabled = true
		} else {
			allEnabled = false
		}
	}
	f.FirewallState = "Disabled"
	if allEnabled && len(profiles) > 0 {
		f.FirewallState = "Enabled"
	} else if anyEnabled {
		f.FirewallState = "Partially Enabled"
	}
	return f
}

func collectEDRInfo() shared.EDRXDRDetectionInfo {
	var info shared.EDRXDRDetectionInfo
	knownEDR := []struct {
		svc    string
		name   string
		vendor string
		proc   string
	}{
		{"falcon-sensor", "CrowdStrike Falcon", "CrowdStrike", "falcon-sensor"},
		{"sentinelone", "SentinelOne Singularity", "SentinelOne", "sentineld"},
		{"wazuh-agent", "Wazuh Agent", "Wazuh", "wazuh-agentd"},
		{"velociraptor", "Velociraptor", "Velociraptor", "velociraptor"},
		{"osqueryd", "Osquery", "Osquery", "osqueryd"},
	}

	runningProcs := make(map[string]bool)
	if entries, err := os.ReadDir("/proc"); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			var pid int
			if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err == nil {
				if comm, err := os.ReadFile("/proc/" + e.Name() + "/comm"); err == nil {
					runningProcs[strings.TrimSpace(string(comm))] = true
				}
			}
		}
	}

	for _, e := range knownEDR {
		installed := false
		status := "Stopped"
		startup := "Disabled"

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
		
		if !installed {
			continue
		}
		
		agent := shared.EDRXDRAgentDetails{
			AgentName:              e.name,
			Vendor:                 e.vendor,
			ServiceStatus:          status,
			HealthStatus:           "Healthy",
			ConnectivityStatus:     "Connected",
			TamperProtectionStatus: "Enabled",
			Installed:              true,
			Running:                status == "Running",
			Stopped:                status == "Stopped",
			Disabled:               startup == "Disabled",
		}
		
		if status == "Running" {
			agent.CloudConnected = true
			agent.Healthy = true
		} else {
			agent.HealthStatus = "Unhealthy"
			agent.ConnectivityStatus = "Disconnected"
			agent.CloudDisconnected = true
			agent.Offline = true
		}
		
		info.Agents = append(info.Agents, agent)
	}
	return info
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

func collectIdentityAccessControl() shared.IdentityAccessControlInfo {
	var id shared.IdentityAccessControlInfo
	id.SSHRootLogin = "Unknown"
	id.SSHPasswordAuth = "Unknown"
	id.SudoPrivilege = "Unknown"

	if data, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			l := strings.TrimSpace(line)
			if strings.HasPrefix(l, "#") {
				continue
			}
			fields := strings.Fields(l)
			if len(fields) >= 2 {
				key := strings.ToLower(fields[0])
				val := strings.ToLower(fields[1])
				if key == "permitrootlogin" {
					if val == "yes" {
						id.SSHRootLogin = "Enabled"
					} else if val == "no" || val == "prohibit-password" {
						id.SSHRootLogin = "Disabled"
					}
				}
				if key == "passwordauthentication" {
					if val == "yes" {
						id.SSHPasswordAuth = "Enabled"
					} else if val == "no" {
						id.SSHPasswordAuth = "Disabled"
					}
				}
			}
		}
	}

	if data, err := os.ReadFile("/etc/group"); err == nil {
		id.SudoPrivilege = "Configured"
		hasSudoGroup := false
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Split(line, ":")
			if len(parts) >= 4 {
				gname := parts[0]
				if gname == "sudo" || gname == "wheel" {
					hasSudoGroup = true
				}
			}
		}
		if !hasSudoGroup {
			id.SudoPrivilege = "Misconfigured"
		}
	}

	// Query Linux Pending Security Updates
	id.PatchComplianceStatus = "Compliant"
	id.PendingSecurityPatches = 0
	
	if _, err := os.Stat("/usr/lib/update-notifier/apt-check"); err == nil {
		if out, errRun := shared.RunCommand("/usr/lib/update-notifier/apt-check"); errRun == nil {
			parts := strings.Split(strings.TrimSpace(out), ";")
			if len(parts) >= 2 {
				var sec int
				if _, errSc := fmt.Sscanf(parts[1], "%d", &sec); errSc == nil {
					id.PendingSecurityPatches = sec
				}
			}
		}
	} else if _, errApt := os.Stat("/usr/bin/apt-get"); errApt == nil {
		if out, errRun := shared.RunCommand("apt-get", "-s", "upgrade"); errRun == nil {
			count := 0
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(strings.ToLower(line), "-security") || strings.Contains(strings.ToLower(line), "security") {
					count++
				}
			}
			id.PendingSecurityPatches = count
		}
	} else if _, errYum := os.Stat("/usr/bin/yum"); errYum == nil {
		if out, errRun := shared.RunCommand("yum", "check-update", "--security"); errRun == nil {
			count := 0
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(strings.ToLower(line), "security") && (strings.Contains(line, ".") || strings.Contains(line, "-")) {
					count++
				}
			}
			id.PendingSecurityPatches = count
		}
	}
	
	if id.PendingSecurityPatches > 0 {
		id.PatchComplianceStatus = "Non-Compliant"
	}

	return id
}

func collectNetworkExposure(ports []shared.ListeningPort) shared.NetworkExposureAccessInfo {
	info := analyzeNetworkExposure(ports)
	
	id := collectIdentityAccessControl()
	info.SSHRootLoginStatus = id.SSHRootLogin
	info.SSHPasswordAuthStatus = id.SSHPasswordAuth
	
	info.SSHKeyAuthStatus = "Unknown"
	if data, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			l := strings.TrimSpace(line)
			if strings.HasPrefix(l, "#") {
				continue
			}
			fields := strings.Fields(l)
			if len(fields) >= 2 {
				key := strings.ToLower(fields[0])
				val := strings.ToLower(fields[1])
				if key == "pubkeyauthentication" {
					if val == "yes" {
						info.SSHKeyAuthStatus = "Enabled"
					} else if val == "no" {
						info.SSHKeyAuthStatus = "Disabled"
					}
				}
			}
		}
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
	if _, err := shared.RunCommand("iptables", "-L", "-n"); err == nil {
		return []shared.FirewallProfile{{Name: "iptables", Enabled: true}}
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
