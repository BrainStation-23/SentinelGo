package security

import (
	"encoding/json"
	"os"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// Seams for the command runner and filesystem probes used by this file. They
// are variables only so tests can substitute canned output and a fake
// filesystem; production always uses the real implementations.
var (
	darwinRunCommand = shared.RunCommand
	darwinStat       = os.Stat
	darwinReadFile   = os.ReadFile
)

const avCrowdStrikeFalcon = "CrowdStrike Falcon"

// knownAVApps maps known AV installation paths to product names.
var knownAVApps = []struct {
	path string
	name string
}{
	{"/Applications/Malwarebytes.app", "Malwarebytes"},
	{"/Applications/Falcon.app", avCrowdStrikeFalcon},
	{"/Library/CS/falconctl", avCrowdStrikeFalcon},
	{"/Library/Application Support/CrowdStrike/Falcon", avCrowdStrikeFalcon},
	{"/Applications/SentinelOne Extensions.app", "SentinelOne"},
	{"/Applications/ESET Endpoint Security.app", "ESET Endpoint Security"},
	{"/Applications/Sophos/Sophos Anti-Virus.app", "Sophos AV"},
	{"/Library/Sophos Anti-Virus Extension", "Sophos AV"},
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
	avProtection.XProtectVersion = detectXProtectVersion()
	avProtection.MRTInstalled = detectMRTInstalled()
	if avProtection.MRTInstalled {
		avProtection.Products = append(avProtection.Products, buildMRTDetails())
	}

	edrXdr := collectEDRInfo()
	kernelHard := shared.KernelHardeningInfo{
		MemoryIntegrityEnabled: false,
		VBSEnabled:             false,
		SIPEnabled:             coreIsolation.SIPEnabled,
		USBMassStorageEnabled:  usb,
	}
	devEnc := collectDeviceEncryption()
	hwSec := collectHardwareSecurity()
	idAccess := collectIdentityAccessControl()
	netExposure := analyzeNetworkExposure(ports)

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
// summary.
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

// detectXProtectVersion reads the XProtect bundle version from either of its
// two known install locations.
func detectXProtectVersion() string {
	if out, err := darwinRunCommand("defaults", "read", "/System/Library/CoreServices/XProtect.bundle/Contents/Info", "CFBundleShortVersionString"); err == nil {
		return strings.TrimSpace(out)
	}
	if out, err := darwinRunCommand("defaults", "read", "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info", "CFBundleShortVersionString"); err == nil {
		return strings.TrimSpace(out)
	}
	return ""
}

// detectMRTInstalled reports whether Apple's Malware Removal Tool is present
// at either of its two known install locations.
func detectMRTInstalled() bool {
	if _, err := darwinStat("/System/Library/CoreServices/MRT.app"); err == nil {
		return true
	}
	_, err := darwinStat("/Library/Apple/System/Library/CoreServices/MRT.app")
	return err == nil
}

// buildMRTDetails builds the Malware Removal Tool antivirus entry, including
// scan details parsed from its log.
func buildMRTDetails() shared.AntivirusDetails {
	scan := collectMRTScanInfo()
	return shared.AntivirusDetails{
		ProductName:             "Malware Removal Tool",
		Vendor:                  "Apple",
		Version:                 "Unknown",
		RealTimeProtectionState: "Enabled",
		ServiceStatus:           "Running",
		UpdateStatus:            "Unknown",
		ScanInfo:                &scan,
	}
}

// collectMRTScanInfo reads /var/log/MRT.log and reports the timestamp and
// outcome of the most recent scan, based on the last non-empty log line.
func collectMRTScanInfo() shared.SecurityScanInfo {
	var scan shared.SecurityScanInfo
	scan.LastScanTime = "Unknown"
	scan.ScanType = "On-Access"
	scan.ScanResult = "Clean"

	mlog, err := darwinReadFile("/var/log/MRT.log")
	if err != nil {
		return scan
	}
	lines := strings.Split(string(mlog), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		parseMRTLogLine(line, &scan)
		break
	}
	return scan
}

// parseMRTLogLine extracts the timestamp from an MRT.log line and flags a
// threat when the line reports a removal.
func parseMRTLogLine(line string, scan *shared.SecurityScanInfo) {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) >= 2 {
		scan.LastScanTime = parts[0] + " " + parts[1]
	}
	if strings.Contains(strings.ToLower(line), "removing") || strings.Contains(strings.ToLower(line), "removed") {
		scan.ScanResult = "Threats Detected"
		scan.RecentThreats = append(scan.RecentThreats, shared.ThreatDetails{
			ThreatName:    "Malware",
			Severity:      "High",
			FilePath:      "Check /var/log/MRT.log",
			ActionTaken:   "Removed",
			DetectionTime: scan.LastScanTime,
		})
	}
}

func collectEDRInfo() shared.EDRXDRDetectionInfo {
	var info shared.EDRXDRDetectionInfo
	knownEDR := []struct {
		path   string
		proc   string
		name   string
		vendor string
	}{
		{"/Library/CS/falconctl", "falcon-sensor", "CrowdStrike Falcon", "CrowdStrike"},
		{"/Applications/SentinelOne Extensions.app", "sentineld", "SentinelOne Singularity", "SentinelOne"},
		{"/Library/LaunchDaemons/com.wazuh.agent.plist", "wazuh-agent", "Wazuh Agent", "Wazuh"},
		{"/var/ossec", "wazuh-agent", "Wazuh Agent", "Wazuh"},
		{"/usr/local/bin/velociraptor", "velociraptor", "Velociraptor", "Velociraptor"},
		{"/var/db/osquery", "osqueryd", "Osquery", "Osquery"},
		{"/opt/osquery", "osqueryd", "Osquery", "Osquery"},
	}

	runningProcs := make(map[string]bool)
	if psOut, err := darwinRunCommand("ps", "-axco", "comm"); err == nil {
		for _, line := range strings.Split(psOut, "\n") {
			runningProcs[strings.TrimSpace(line)] = true
		}
	}

	for _, e := range knownEDR {
		installed := false
		if _, err := darwinStat(e.path); err == nil {
			installed = true
		} else if runningProcs[e.proc] {
			installed = true
		}

		if !installed {
			continue
		}

		isRunning := runningProcs[e.proc]
		status := "Stopped"
		if isRunning {
			status = "Running"
		}

		agent := shared.EDRXDRAgentDetails{
			AgentName:              e.name,
			Vendor:                 e.vendor,
			AgentVersion:           "Unknown",
			ServiceStatus:          status,
			HealthStatus:           "Healthy",
			ConnectivityStatus:     "Unknown",
			TamperProtectionStatus: "Unknown",
			Installed:              true,
			Running:                isRunning,
			Stopped:                !isRunning,
		}

		if isRunning {
			agent.Healthy = true
		} else {
			agent.HealthStatus = "Unhealthy"
			agent.Unhealthy = true
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

	output, err := darwinRunCommand("fdesetup", "status")
	if err == nil {
		lower := strings.ToLower(output)
		if strings.Contains(lower, "filevault is on") {
			enc.EncryptionProvider = "FileVault"
			enc.EncryptionStatus = "Encrypted"
			enc.ProtectionStatus = "Enabled"
		}

		keyOut, keyErr := darwinRunCommand("fdesetup", "haspersonalrecoverykey")
		if keyErr == nil && strings.Contains(strings.ToLower(keyOut), "true") {
			enc.RecoveryKeyBackupStatus = "Backed Up"
		}
	}
	return enc
}

func collectHardwareSecurity() shared.HardwareSecurityInfo {
	var hw shared.HardwareSecurityInfo
	hw.TPMStatus = "Unsupported"
	hw.TPMVersion = "None"
	hw.SecureBootStatus = collectSecureBoot()

	hw.SecureEnclaveStatus = "Unsupported"
	hw.ActivationLockStatus = "Unknown"

	hwOut, err := darwinRunCommand("system_profiler", "SPHardwareDataType")
	if err == nil {
		lower := strings.ToLower(hwOut)
		if strings.Contains(lower, "apple silicon") || strings.Contains(lower, "apple m") || strings.Contains(lower, "t2") {
			hw.SecureEnclaveStatus = "Enabled"
		}

		for _, line := range strings.Split(hwOut, "\n") {
			if strings.Contains(line, "Activation Lock Status:") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					hw.ActivationLockStatus = strings.TrimSpace(parts[1])
				}
			}
		}
	}
	return hw
}

func collectIdentityAccessControl() shared.IdentityAccessControlInfo {
	var id shared.IdentityAccessControlInfo

	id.TouchIDStatus = "Disabled"
	if out, err := darwinRunCommand("bioutil", "-read", "-system"); err == nil {
		if strings.Contains(strings.ToLower(out), "enabled") {
			id.TouchIDStatus = "Enabled"
		}
	}

	id.BootstrapTokenStatus = "Disabled"
	if out, err := darwinRunCommand("profiles", "status", "-type", "bootstraptoken"); err == nil {
		if strings.Contains(strings.ToLower(out), "supported: yes") || strings.Contains(strings.ToLower(out), "escrowed: yes") {
			id.BootstrapTokenStatus = "Enabled"
		}
	}

	id.SecureTokenStatus = "Unknown"
	currentUser := os.Getenv("USER")
	if currentUser == "" {
		currentUser = os.Getenv("LOGNAME") // fallback when running as a launchd service
	}
	if currentUser != "" {
		if out, err := darwinRunCommand("sysadminctl", "-secureTokenStatus", currentUser); err == nil {
			if strings.Contains(strings.ToLower(out), "is enabled") {
				id.SecureTokenStatus = "Enabled"
			} else if strings.Contains(strings.ToLower(out), "is disabled") {
				id.SecureTokenStatus = "Disabled"
			}
		}
	}

	// Query macOS Software Update status.
	// Only mark Non-Compliant when a security-labelled update is listed.
	// "Recommended" and "restart" appear in ordinary updates and must not
	// trigger a false Non-Compliant result.
	id.PatchComplianceStatus = "Compliant"
	id.RapidSecurityResponses = "Up to Date"
	if out, err := darwinRunCommand("softwareupdate", "-l"); err == nil {
		lower := strings.ToLower(out)
		if strings.Contains(lower, "security") {
			id.PatchComplianceStatus = "Non-Compliant"
			// Only flag RSR as out of date for actual Rapid Security Responses.
			if strings.Contains(lower, "rapid security") || strings.Contains(lower, "security response") {
				id.RapidSecurityResponses = "Out of Date"
			}
		}
	}

	return id
}

// collectAV checks for known AV app bundles and reports Gatekeeper status.
func collectAV() []shared.AntivirusProduct {
	var products []shared.AntivirusProduct
	seen := map[string]bool{}

	for _, app := range knownAVApps {
		if seen[app.name] {
			continue
		}
		if _, err := darwinStat(app.path); err == nil {
			seen[app.name] = true
			products = append(products, shared.AntivirusProduct{
				Name:     app.name,
				Enabled:  "unknown",
				UpToDate: "unknown",
				Source:   "process",
			})
		}
	}

	// Gatekeeper: macOS built-in application assessment.
	gkEnabled := "disabled"
	if output, err := darwinRunCommand("spctl", "--status"); err == nil {
		if strings.Contains(strings.ToLower(output), "assessments enabled") {
			gkEnabled = "enabled"
		}
	}
	products = append(products, shared.AntivirusProduct{
		Name:     "Gatekeeper",
		Enabled:  gkEnabled,
		UpToDate: "unknown",
		Source:   "gatekeeper",
	})

	return products
}

// collectFirewallProfiles queries the macOS Application Firewall state.
func collectFirewallProfiles() []shared.FirewallProfile {
	output, err := darwinRunCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
	if err != nil {
		return nil
	}
	lower := strings.ToLower(strings.TrimSpace(output))
	enabled := strings.Contains(lower, "enabled")
	return []shared.FirewallProfile{{Name: "Application Firewall", Enabled: enabled}}
}

func collectCoreIsolation() shared.CoreIsolationInfo {
	return shared.CoreIsolationInfo{
		SIPEnabled: collectSIP(),
	}
}

// collectSIP reports the System Integrity Protection state via csrutil.
func collectSIP() string {
	output, err := darwinRunCommand("csrutil", "status")
	if err != nil {
		return "unknown"
	}
	lower := strings.ToLower(strings.TrimSpace(output))
	if strings.Contains(lower, "enabled") {
		return "enabled"
	}
	if strings.Contains(lower, "disabled") {
		return "disabled"
	}
	return "unknown"
}

// collectSecureBoot infers Secure Boot state from the iBridge/T2 data type.
// On T2 and Apple Silicon, Secure Boot is always present; the active security
// policy ("Full Security", "Reduced Security", "No Security") determines enforcement.
func collectSecureBoot() string {
	output, err := darwinRunCommand("system_profiler", "SPiBridgeDataType")
	if err != nil {
		return "unknown"
	}
	lower := strings.ToLower(output)
	if strings.Contains(lower, "no security") {
		return "disabled"
	}
	if strings.Contains(lower, "full security") || strings.Contains(lower, "reduced security") {
		return "enabled"
	}
	// T2/Apple Silicon detected but security policy not explicitly stated.
	if strings.Contains(lower, "bridge os") || strings.Contains(lower, "apple t") {
		return "enabled"
	}
	return "unknown"
}

// collectUSBMassStorage checks whether USB mass storage is permitted on macOS.
// On MDM-managed devices, plutil can read the applicationaccess managed preference
// plist and report the allowUSBRestricted policy directly. On unmanaged devices,
// a loaded IOUSBMassStorageClass kext confirms mass storage is active; otherwise
// the state cannot be determined without root or MDM access.
func collectUSBMassStorage() string {
	if state := usbStateFromMDM(); state != "" {
		return state
	}
	if kstat, err := darwinRunCommand("kextstat"); err == nil {
		if strings.Contains(kstat, "IOUSBMassStorageClass") {
			return "enabled"
		}
	}
	return "unknown"
}

// usbStateFromMDM reads the allowUSBRestricted key from the MDM-managed
// applicationaccess preference plist. Returns "" when the plist is absent,
// unreadable, or does not contain the key.
func usbStateFromMDM() string {
	out, err := darwinRunCommand("plutil", "-convert", "json", "-o", "-",
		"/Library/Managed Preferences/com.apple.applicationaccess.plist")
	if err != nil {
		return ""
	}
	return parseAllowUSBRestrictedJSON(out)
}

// parseAllowUSBRestrictedJSON extracts the allowUSBRestricted bool from a JSON
// string produced by plutil. Returns "enabled", "disabled", or "" if the key is
// absent or the input is not valid JSON.
func parseAllowUSBRestrictedJSON(jsonStr string) string {
	var prefs map[string]interface{}
	if json.Unmarshal([]byte(jsonStr), &prefs) != nil {
		return ""
	}
	v, ok := prefs["allowUSBRestricted"]
	if !ok {
		return ""
	}
	allowed, ok := v.(bool)
	if !ok {
		return ""
	}
	if allowed {
		return "enabled"
	}
	return "disabled"
}
