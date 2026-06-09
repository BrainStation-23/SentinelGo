package software

import (
	"context"
	"encoding/json"
	"log"
	"os/exec"
	"time"
)

// platformSoftware collects installed software on Windows.
func (s *SoftwareService) platformSoftware() []SoftwareInfo {
	var sw []SoftwareInfo
	sw = append(sw, s.getWindowsSoftware()...)
	sw = append(sw, s.getWindowsStoreApps()...)
	sw = append(sw, s.getChromeExtensions()...)
	sw = append(sw, s.getFirefoxExtensions()...)
	sw = append(sw, s.getEdgeExtensions()...)
	sw = append(sw, s.getBraveExtensions()...)
	return sw
}

func (s *SoftwareService) getWindowsSoftware() []SoftwareInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	registryQuery := `$paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; Get-ItemProperty $paths | Where-Object {$_.DisplayName} | Select-Object @{N='Name';E={$_.DisplayName}},@{N='Version';E={$_.DisplayVersion}},@{N='InstallLocation';E={$_.InstallLocation}} | ConvertTo-Json`
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", registryQuery)
	output, err := cmd.Output()
	if err != nil {
		log.Printf("software: registry uninstall query failed: %v", err)
		return nil
	}

	var result []SoftwareInfo
	parsePowerShellOutput(output, &result, "programs")
	return result
}

func (s *SoftwareService) getWindowsStoreApps() []SoftwareInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	query := `Get-AppxPackage | Where-Object {$_.SignatureKind -ne "System"} | Select-Object @{N='Name';E={$_.Name}},@{N='Version';E={$_.Version}},@{N='InstallLocation';E={$_.InstallLocation}} | ConvertTo-Json`
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", query)
	output, err := cmd.Output()
	if err != nil {
		log.Printf("software: Get-AppxPackage failed: %v", err)
		return nil
	}
	var result []SoftwareInfo
	parsePowerShellOutput(output, &result, "microsoft_store")
	return result
}

func parsePowerShellOutput(output []byte, software *[]SoftwareInfo, source string) {
	var psOutput []map[string]any
	if err := json.Unmarshal(output, &psOutput); err != nil {
		var single map[string]any
		if err2 := json.Unmarshal(output, &single); err2 != nil {
			return
		}
		psOutput = []map[string]any{single}
	}

	for _, item := range psOutput {
		name, ok := item["Name"].(string)
		if !ok {
			continue
		}
		version, _ := item["Version"].(string)
		installLocation, _ := item["InstallLocation"].(string)

		now := time.Now().Format(time.RFC3339)
		*software = append(*software, SoftwareInfo{
			Name:             name,
			InstalledVersion: version,
			FilePath:         installLocation,
			Source:           source,
			Type:             source,
			Status:           "installed",
			FirstSeenAt:      now,
			LastSeenAt:       now,
			IsActive:         true,
		})
	}
}

// chromeExtDirGlobs returns Chrome extension directory glob patterns on Windows.
func chromeExtDirGlobs(home string) []string {
	return []string{
		home + `\AppData\Local\Google\Chrome\User Data\Default\Extensions`,
		home + `\AppData\Local\Google\Chrome\User Data\Profile *\Extensions`,
	}
}

// edgeExtDirGlobs returns Edge extension directory glob patterns on Windows.
func edgeExtDirGlobs(home string) []string {
	return []string{
		home + `\AppData\Local\Microsoft\Edge\User Data\Default\Extensions`,
		home + `\AppData\Local\Microsoft\Edge\User Data\Profile *\Extensions`,
	}
}

// braveExtDirGlobs returns Brave extension directory glob patterns on Windows.
func braveExtDirGlobs(home string) []string {
	return []string{
		home + `\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Extensions`,
		home + `\AppData\Local\BraveSoftware\Brave-Browser\User Data\Profile *\Extensions`,
	}
}

// firefoxProfileGlobs returns Firefox profile directory glob patterns on Windows.
func firefoxProfileGlobs(home string) []string {
	return []string{
		home + `\AppData\Roaming\Mozilla\Firefox\Profiles\*`,
	}
}
