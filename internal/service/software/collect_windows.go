package software

import (
	"context"
	"encoding/json"
	"log"
	"os/exec"
	"time"
)

// platformSoftware collects currently installed software on Windows.
func (s *SoftwareService) platformSoftware() []SoftwareInfo {
	var sw []SoftwareInfo

	if items, ok := s.getWindowsSoftware(); ok {
		sw = append(sw, items...)
	}
	if items, ok := s.getWindowsStoreApps(); ok {
		sw = append(sw, items...)
	}
	s.appendExtensions(&sw)

	// Enrich with last-opened times from UserAssist. Best-effort; failures leave
	// LastOpened empty and never affect which software is reported installed.
	applyLastOpened(sw, getWindowsLastOpened())

	return sw
}

// getWindowsSoftware enumerates installed programs from the registry uninstall keys.
func (s *SoftwareService) getWindowsSoftware() ([]SoftwareInfo, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), collectCmdTimeout)
	defer cancel()

	registryQuery := `$paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; Get-ItemProperty $paths | Where-Object {$_.DisplayName} | Select-Object @{N='Name';E={$_.DisplayName}},@{N='Version';E={$_.DisplayVersion}},@{N='InstallLocation';E={$_.InstallLocation}},@{N='InstallDate';E={$_.InstallDate}} | ConvertTo-Json`
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", registryQuery)
	output, err := cmd.Output()
	if err != nil {
		log.Printf("software: registry uninstall query failed: %v", err)
		return nil, false
	}

	var result []SoftwareInfo
	ok := parsePowerShellOutput(output, &result, "programs")
	return result, ok
}

func (s *SoftwareService) getWindowsStoreApps() ([]SoftwareInfo, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), collectCmdTimeout)
	defer cancel()

	query := `Get-AppxPackage | Where-Object {$_.SignatureKind -ne "System"} | Select-Object @{N='Name';E={$_.Name}},@{N='Version';E={$_.Version}},@{N='InstallLocation';E={$_.InstallLocation}} | ConvertTo-Json`
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", query)
	output, err := cmd.Output()
	if err != nil {
		log.Printf("software: Get-AppxPackage failed: %v", err)
		return nil, false
	}
	var result []SoftwareInfo
	ok := parsePowerShellOutput(output, &result, "microsoft_store")
	return result, ok
}

// parsePowerShellOutput parses a ConvertTo-Json software list into SoftwareInfo entries.
// Returns false when the output could not be parsed as JSON.
func parsePowerShellOutput(output []byte, software *[]SoftwareInfo, source string) bool {
	var psOutput []map[string]any
	if err := json.Unmarshal(output, &psOutput); err != nil {
		var single map[string]any
		if err2 := json.Unmarshal(output, &single); err2 != nil {
			return false
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

		now := time.Now().UTC().Format(time.RFC3339)
		firstSeen := now
		if installDate, _ := item["InstallDate"].(string); installDate != "" {
			if t, err := time.Parse("20060102", installDate); err == nil {
				firstSeen = t.UTC().Format(time.RFC3339)
			}
		}
		*software = append(*software, SoftwareInfo{
			Name:             name,
			InstalledVersion: version,
			FilePath:         installLocation,
			Source:           source,
			Type:             source,
			FirstSeenAt:      firstSeen,
		})
	}
	return true
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
