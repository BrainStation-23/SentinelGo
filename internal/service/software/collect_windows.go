package software

import (
	"context"
	"encoding/json"
	"log"
	"os/exec"
	"time"
)

// platformSoftware collects installed software on Windows along with the set of
// source categories that were authoritatively scanned this cycle. A source only
// appears in the returned map when its scan actually succeeded, so that a failed
// enumeration never causes its software to be reconciled as uninstalled.
func (s *SoftwareService) platformSoftware() ([]SoftwareInfo, map[string]bool) {
	scanned := make(map[string]bool)
	var sw []SoftwareInfo

	if items, ok := s.getWindowsSoftware(); ok {
		sw = append(sw, items...)
		scanned["programs"] = true
	}
	if items, ok := s.getWindowsStoreApps(); ok {
		sw = append(sw, items...)
		scanned["microsoft_store"] = true
	}
	s.appendExtensions(&sw, scanned)

	// Enrich with last-opened times from UserAssist. This is best-effort and runs
	// outside the enumeration path: any failure leaves LastOpened empty and never
	// affects which software is considered installed.
	applyLastOpened(sw, getWindowsLastOpened())

	return sw, scanned
}

// getWindowsSoftware enumerates installed programs from the registry uninstall
// keys. The query is intentionally limited to fast, authoritative fields — no
// per-program filesystem walks — so it stays well within its timeout. The bool is
// true only when the query ran and its output parsed; last-opened is collected
// separately (see getWindowsLastOpened).
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

// parsePowerShellOutput parses a ConvertTo-Json software list into software.
// It returns false when the output could not be parsed as JSON (a failed or
// empty query), which the caller treats as "source not scanned" so the catalog
// is preserved rather than reconciled against an empty result.
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
			Status:           "installed",
			FirstSeenAt:      firstSeen,
			LastSeenAt:       now,
			IsActive:         true,
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
