package security

import (
	"encoding/json"
	"fmt"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

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
		if strings.EqualFold(av.UpToDate, "yes") {
			details.UpdateStatus = "Up to Date"
		} else if strings.EqualFold(av.UpToDate, "no") {
			details.UpdateStatus = "Out of Date"
		}
		avProtection.Products = append(avProtection.Products, details)
	}
	avProtection.WindowsDefenderDetails = collectWindowsDefenderDetails()

	edrXdr := collectEDRInfo()
	kernelHard := shared.KernelHardeningInfo{
		MemoryIntegrityEnabled: coreIsolation.MemoryIntegrityEnabled,
		VBSEnabled:             coreIsolation.VBSEnabled,
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

func collectWindowsDefenderDetails() *shared.WindowsDefenderDetails {
	output, err := shared.RunCommand("powershell", "-NoProfile", "-Command",
		"Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,IsTamperProtected,AntivirusSignatureLastUpdated,ControlledFolderAccessEnabled,LastQuickScanTime,LastFullScanTime | ConvertTo-Json -Compress")
	if err != nil {
		return nil
	}
	var details shared.WindowsDefenderDetails
	var raw map[string]interface{}
	if json.Unmarshal([]byte(strings.TrimSpace(output)), &raw) == nil {
		rtEnabled, _ := raw["RealTimeProtectionEnabled"].(bool)
		tamper, _ := raw["IsTamperProtected"].(bool)

		cfaVal := raw["ControlledFolderAccessEnabled"]
		if cfaBool, ok := cfaVal.(bool); ok {
			details.ControlledFolderAccess = cfaBool
		} else if cfaNum, ok := cfaVal.(float64); ok {
			details.ControlledFolderAccess = cfaNum != 0
		}

		details.RealTimeProtectionEnabled = rtEnabled
		details.TamperProtectionEnabled = tamper

		sigTime, _ := raw["AntivirusSignatureLastUpdated"].(string)
		details.SignatureLastUpdated = sigTime

		details.SmartScreenEnabled = queryRegistryBool(
			`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer`,
			"SmartScreenEnabled") || queryRegistryBool(
			`HKLM\SOFTWARE\Policies\Microsoft\Windows\System`,
			"EnableSmartScreen")

		asrOutput, asrErr := shared.RunCommand("reg", "query", `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules`)
		if asrErr == nil {
			lines := strings.Split(asrOutput, "\n")
			count := 0
			for _, l := range lines {
				if strings.Contains(l, "REG_SZ") {
					count++
				}
			}
			details.ASRRulesCount = count
		}

		var scan shared.SecurityScanInfo
		scan.LastScanTime = "Unknown"
		scan.ScanType = "Unknown"
		scan.ScanResult = "Clean"

		lastQuick, _ := raw["LastQuickScanTime"].(string)
		lastFull, _ := raw["LastFullScanTime"].(string)

		if lastFull != "" && !strings.Contains(lastFull, "1601") {
			scan.LastScanTime = lastFull
			scan.ScanType = "Full Scan"
		} else if lastQuick != "" && !strings.Contains(lastQuick, "1601") {
			scan.LastScanTime = lastQuick
			scan.ScanType = "Quick Scan"
		}

		threatsOutput, threatsErr := shared.RunCommand("powershell", "-NoProfile", "-Command",
			"Get-CimInstance -Namespace root/Microsoft/Windows/Defender -ClassName MSFT_MpThreatDetection | Select-Object ThreatName,SeverityID,InitialDetectionTime,ActionID | ConvertTo-Json -Compress")
		if threatsErr == nil && strings.TrimSpace(threatsOutput) != "" {
			var rawThreats []map[string]interface{}
			var singleThreat map[string]interface{}
			if json.Unmarshal([]byte(threatsOutput), &rawThreats) != nil {
				if json.Unmarshal([]byte(threatsOutput), &singleThreat) == nil {
					rawThreats = []map[string]interface{}{singleThreat}
				}
			}
			for _, rt := range rawThreats {
				name, _ := rt["ThreatName"].(string)
				if name == "" {
					continue
				}
				var severityVal float64
				if sev, ok := rt["SeverityID"].(float64); ok {
					severityVal = sev
				}
				var actionVal float64
				if act, ok := rt["ActionID"].(float64); ok {
					actionVal = act
				}
				detTime, _ := rt["InitialDetectionTime"].(string)

				severity := "Unknown"
				switch int(severityVal) {
				case 1:
					severity = "Low"
				case 2:
					severity = "Medium"
				case 4:
					severity = "High"
				case 5:
					severity = "Critical"
				}

				action := "Detected"
				switch int(actionVal) {
				case 1:
					action = "Cleaned"
				case 2:
					action = "Quarantined"
				case 3:
					action = "Removed"
				case 6:
					action = "Allowed"
				}

				scan.RecentThreats = append(scan.RecentThreats, shared.ThreatDetails{
					ThreatName:    name,
					Severity:      severity,
					FilePath:      "Unknown",
					ActionTaken:   action,
					DetectionTime: detTime,
				})
				scan.ScanResult = "Threats Detected"
			}
		}
		details.ScanInfo = &scan
	}
	return &details
}

func queryServiceStatus(svcName string) (exists bool, status string, startup string) {
	out, err := shared.RunCommand("sc.exe", "query", svcName)
	if err != nil {
		return false, "Stopped", "Disabled"
	}
	exists = true
	status = "Unknown"
	if strings.Contains(out, "RUNNING") {
		status = "Running"
	} else if strings.Contains(out, "STOPPED") {
		status = "Stopped"
	}

	qcOut, qcErr := shared.RunCommand("sc.exe", "qc", svcName)
	startup = "Auto"
	if qcErr == nil {
		if strings.Contains(qcOut, "DISABLED") {
			startup = "Disabled"
		} else if strings.Contains(qcOut, "DEMAND_START") {
			startup = "Manual"
		}
	}
	return exists, status, startup
}

func collectEDRInfo() shared.EDRXDRDetectionInfo {
	var info shared.EDRXDRDetectionInfo
	knownEDR := []struct {
		svc    string
		name   string
		vendor string
	}{
		{"CSFalconService", "CrowdStrike Falcon", "CrowdStrike"},
		{"SentinelAgent", "SentinelOne Singularity", "SentinelOne"},
		{"Sense", "Microsoft Defender for Endpoint", "Microsoft"},
		{"cyserver", "Cortex XDR", "Palo Alto Networks"},
		{"cbdaemon", "Carbon Black Cloud", "VMware"},
		{"Sophos System Protection", "Sophos MDR", "Sophos"},
		{"Elastic Agent", "Elastic Agent", "Elastic"},
		{"Wazuh", "Wazuh Agent", "Wazuh"},
		{"ir_agent", "Insight Agent", "Rapid7"},
		{"ArcticWolfAgent", "Arctic Wolf Agent", "Arctic Wolf"},
		{"HuntressAgent", "Huntress Agent", "Huntress"},
		{"CybereasonActiveProbe", "Cybereason", "Cybereason"},
		{"FortiEDRService", "FortiEDR", "Fortinet"},
		{"DesktopCentralAgent", "Endpoint Central Agent", "ManageEngine"},
		{"Velociraptor", "Velociraptor", "Velociraptor"},
		{"osqueryd", "Osquery", "Osquery"},
	}

	for _, e := range knownEDR {
		exists, status, startup := queryServiceStatus(e.svc)
		if !exists {
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

		if status != "Running" {
			agent.HealthStatus = "Unhealthy"
			agent.ConnectivityStatus = "Disconnected"
			agent.CloudDisconnected = true
			agent.Offline = true
		} else {
			agent.CloudConnected = true
			agent.Healthy = true
		}

		if startup == "Disabled" {
			agent.Disabled = true
			agent.HealthStatus = "Unhealthy"
		}

		if e.svc == "CSFalconService" {
			vOut, vErr := shared.RunCommand("reg", "query", `HKLM\SOFTWARE\CrowdStrike\Falcon`, "/v", "version")
			if vErr == nil {
				agent.AgentVersion = parseRegSZ(vOut, "version")
			}
		}
		if agent.AgentVersion == "" {
			agent.AgentVersion = "1.0.0"
		}

		info.Agents = append(info.Agents, agent)
	}
	return info
}

func parseRegSZ(output, valueName string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(strings.ToLower(line), strings.ToLower(valueName)) {
			continue
		}
		parts := strings.Fields(line)
		for i, p := range parts {
			if strings.EqualFold(p, "REG_SZ") && i+1 < len(parts) {
				return strings.Join(parts[i+1:], " ")
			}
		}
	}
	return ""
}

func collectDeviceEncryption() shared.DeviceEncryptionInfo {
	var enc shared.DeviceEncryptionInfo
	enc.EncryptionProvider = "None"
	enc.EncryptionStatus = "Unencrypted"
	enc.ProtectionStatus = "Disabled"
	enc.RecoveryKeyBackupStatus = "Unknown"

	output, err := shared.RunCommand("manage-bde", "-status", "C:")
	if err != nil {
		output, err = shared.RunCommand("manage-bde", "-status")
	}
	if err == nil {
		lower := strings.ToLower(output)
		if strings.Contains(lower, "bitlocker version") {
			enc.EncryptionProvider = "BitLocker"
		}
		if strings.Contains(lower, "percentage encrypted: 100") || strings.Contains(lower, "fully encrypted") {
			enc.EncryptionStatus = "Encrypted"
		} else if strings.Contains(lower, "percentage encrypted:") {
			enc.EncryptionStatus = "Partially Encrypted"
		}
		if strings.Contains(lower, "protection on") {
			enc.ProtectionStatus = "Enabled"
		} else if strings.Contains(lower, "protection off") {
			enc.ProtectionStatus = "Disabled"
		}

		fveOut, fveErr := shared.RunCommand("reg", "query", `HKLM\SOFTWARE\Policies\Microsoft\FVE`)
		if fveErr == nil {
			if strings.Contains(fveOut, "RequireBackupToADDS") || strings.Contains(fveOut, "BackupToAAD") {
				enc.RecoveryKeyBackupStatus = "Backed Up"
			}
		}
	}
	return enc
}

func collectHardwareSecurity() shared.HardwareSecurityInfo {
	var hw shared.HardwareSecurityInfo
	hw.SecureBootStatus = collectSecureBoot()

	tpmOut, err := shared.RunCommand("powershell", "-NoProfile", "-Command",
		"Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftTpm -ClassName Win32_Tpm | Select-Object IsEnabled_InitialValue,SpecVersion | ConvertTo-Json -Compress")
	hw.TPMStatus = "Unsupported"
	hw.TPMVersion = "None"
	if err == nil && strings.TrimSpace(tpmOut) != "" {
		var raw map[string]interface{}
		if json.Unmarshal([]byte(strings.TrimSpace(tpmOut)), &raw) == nil {
			hw.TPMStatus = "Disabled"
			enabled, _ := raw["IsEnabled_InitialValue"].(bool)
			if enabled {
				hw.TPMStatus = "Enabled"
			}
			ver, _ := raw["SpecVersion"].(string)
			if ver != "" {
				parts := strings.Split(ver, ",")
				hw.TPMVersion = strings.TrimSpace(parts[0])
			}
		}
	}
	return hw
}

func collectIdentityAccessControl() shared.IdentityAccessControlInfo {
	var id shared.IdentityAccessControlInfo

	helloEnabled := queryRegistryBool(`HKLM\SOFTWARE\Policies\Microsoft\PassportForWork`, "Enabled") ||
		queryRegistryBool(`HKLM\SOFTWARE\Policies\Microsoft\PassportForWork`, "PassportForWork")
	id.WindowsHelloStatus = "Disabled"
	if helloEnabled {
		id.WindowsHelloStatus = "Enabled"
	}

	core := collectCoreIsolation()
	id.CredentialGuardStatus = "Disabled"
	if core.CredentialGuardEnabled {
		id.CredentialGuardStatus = "Enabled"
	}

	id.DeviceGuardStatus = "Disabled"
	if core.VBSEnabled {
		id.DeviceGuardStatus = "Enabled"
	}

	uacVal := parseRegDWORD(
		queryRegistry(`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA"),
		"EnableLUA")
	id.UACStatus = "Disabled"
	if uacVal == 1 {
		id.UACStatus = "Enabled"
	}

	// Query Windows missing Security and Critical updates via COM
	updOut, err := shared.RunCommand("powershell", "-NoProfile", "-Command",
		`$Session = New-Object -ComObject Microsoft.Update.Session; $Searcher = $Session.CreateUpdateSearcher(); $Searcher.Search("IsInstalled=0 and Type='Software'").Updates | Where-Object { $_.Categories | Where-Object { $_.Name -eq 'Security Updates' -or $_.Name -eq 'Critical Updates' } } | Measure-Object | Select-Object -ExpandProperty Count`)

	id.PatchComplianceStatus = "Compliant"
	id.CriticalKBsMissing = 0
	if err == nil {
		var count int
		if _, errSc := fmt.Sscanf(strings.TrimSpace(updOut), "%d", &count); errSc == nil {
			id.CriticalKBsMissing = count
			if count > 0 {
				id.PatchComplianceStatus = "Non-Compliant"
			}
		}
	}

	return id
}

func queryRegistry(keyPath, valueName string) string {
	out, err := shared.RunCommand("reg", "query", keyPath, "/v", valueName)
	if err != nil {
		return ""
	}
	return out
}

// collectUSBMassStorage checks whether the USB Mass Storage driver (USBSTOR) is
// enabled via its service start type in the registry.
// Group Policy / MDM sets Start=4 (SERVICE_DISABLED) to block removable drives.
func collectUSBMassStorage() string {
	output, err := shared.RunCommand("reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR`, "/v", "Start")
	if err != nil {
		return "unknown"
	}
	return usbStorStartToState(parseRegDWORD(output, "Start"))
}

// usbStorStartToState maps a USBSTOR service Start DWORD value to a state string.
// Start=4 is SERVICE_DISABLED; 0–3 are boot/system/auto/demand (all permit the driver to load).
// parseRegDWORD returns -1 when the value is absent; any other unexpected value → "unknown".
func usbStorStartToState(v int) string {
	switch v {
	case 4:
		return "disabled"
	case 0, 1, 2, 3:
		return "enabled"
	default:
		return "unknown"
	}
}

// collectAV queries Windows Security Center 2 for registered antivirus products.
func collectAV() []shared.AntivirusProduct {
	output, err := shared.RunCommand("powershell", "-NoProfile", "-Command",
		"Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState | ConvertTo-Json -Compress")
	if err != nil || strings.TrimSpace(output) == "" {
		return nil
	}
	return parseAVProductsJSON(output)
}

// parseAVProductsJSON decodes ConvertTo-Json output from the SecurityCenter2 query.
// PowerShell returns a JSON object when there is exactly one product, or an array for multiple.
func parseAVProductsJSON(output string) []shared.AntivirusProduct {
	output = strings.TrimSpace(output)
	var raw []map[string]interface{}
	var single map[string]interface{}
	if err := json.Unmarshal([]byte(output), &raw); err != nil {
		if err2 := json.Unmarshal([]byte(output), &single); err2 != nil {
			return nil
		}
		raw = []map[string]interface{}{single}
	}

	var products []shared.AntivirusProduct
	for _, item := range raw {
		name, _ := item["displayName"].(string)
		if name == "" {
			continue
		}
		var state float64
		switch v := item["productState"].(type) {
		case float64:
			state = v
		}
		productState := int(state)

		// productState bitmask:
		//   bits 12-15 (masked): 1 = protection enabled
		//   bits  4-7  (masked): 0 = definitions up-to-date
		enabled := "unknown"
		upToDate := "unknown"
		if productState > 0 {
			if (productState>>12)&0x0F == 1 {
				enabled = "enabled"
			} else {
				enabled = "disabled"
			}
			if (productState>>4)&0x0F == 0 {
				upToDate = "yes"
			} else {
				upToDate = "no"
			}
		}
		products = append(products, shared.AntivirusProduct{
			Name:     strings.TrimSpace(name),
			Enabled:  enabled,
			UpToDate: upToDate,
			Source:   "SecurityCenter2",
		})
	}
	return products
}

// collectFirewallProfiles parses netsh output for Domain/Private/Public profile states.
func collectFirewallProfiles() []shared.FirewallProfile {
	output, err := shared.RunCommand("netsh", "advfirewall", "show", "allprofiles", "state")
	if err != nil {
		return nil
	}
	return parseNetshFirewall(output)
}

// parseNetshFirewall extracts firewall profile states from netsh advfirewall output.
// Example line sequence: "Domain Profile Settings:\n...\nState  ON\n"
func parseNetshFirewall(output string) []shared.FirewallProfile {
	var profiles []shared.FirewallProfile
	var current string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, "Profile Settings:") {
			current = strings.TrimSuffix(line, " Profile Settings:")
		} else if strings.HasPrefix(strings.ToLower(line), "state") && current != "" {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				enabled := strings.EqualFold(parts[len(parts)-1], "ON")
				profiles = append(profiles, shared.FirewallProfile{
					Name:    current,
					Enabled: enabled,
				})
				current = ""
			}
		}
	}
	return profiles
}

// collectCoreIsolation reads Windows Device Guard / HVCI registry values.
func collectCoreIsolation() shared.CoreIsolationInfo {
	return shared.CoreIsolationInfo{
		MemoryIntegrityEnabled: queryRegistryBool(
			`HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`,
			"Enabled"),
		VBSEnabled: queryRegistryBool(
			`HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`,
			"EnableVirtualizationBasedSecurity"),
		CredentialGuardEnabled: queryRegistryBool(
			`HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard`,
			"Enabled"),
	}
}

// queryRegistryBool returns true when the named DWORD registry value equals 1.
func queryRegistryBool(keyPath, valueName string) bool {
	output, err := shared.RunCommand("reg", "query", keyPath, "/v", valueName)
	if err != nil {
		return false
	}
	return parseRegDWORD(output, valueName) == 1
}

// parseRegDWORD extracts the integer value of a REG_DWORD entry from reg query output.
// Expected format: "    ValueName    REG_DWORD    0x1"
func parseRegDWORD(output, valueName string) int {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(strings.ToLower(line), strings.ToLower(valueName)) {
			continue
		}
		parts := strings.Fields(line)
		for i, p := range parts {
			if strings.EqualFold(p, "REG_DWORD") && i+1 < len(parts) {
				var n int
				if _, err := fmt.Sscanf(parts[i+1], "0x%x", &n); err == nil {
					return n
				}
				if _, err := fmt.Sscanf(parts[i+1], "%d", &n); err == nil {
					return n
				}
			}
		}
	}
	return -1
}

// collectSecureBoot reads the UEFI Secure Boot state from the registry.
func collectSecureBoot() string {
	output, err := shared.RunCommand("reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State`,
		"/v", "UEFISecureBootEnabled")
	if err != nil {
		return "unknown"
	}
	switch parseRegDWORD(output, "UEFISecureBootEnabled") {
	case 1:
		return "enabled"
	case 0:
		return "disabled"
	default:
		return "unknown"
	}
}
