package software

import (
	"context"
	"encoding/json"
	"log"
	"os/exec"
	"time"
)

// platformSoftware collects currently installed software on Windows. It returns
// the aggregated list and whether the scan was complete (the registry uninstall
// query — the bulk source — succeeded). An incomplete scan must not be used to
// prune the stored catalog, or a transient PowerShell failure would drop entries.
func (s *SoftwareService) platformSoftware() ([]SoftwareInfo, bool) {
	var sw []SoftwareInfo

	registry, registryOK := s.getWindowsSoftware()
	sw = append(sw, registry...)

	storeApps, _ := s.getWindowsStoreApps()
	sw = append(sw, storeApps...)

	extStart := len(sw)
	s.appendExtensions(&sw)
	extCount := len(sw) - extStart

	// Enrich with last-opened times from UserAssist. Best-effort; failures leave
	// LastOpened empty and never affect which software is reported installed.
	applyLastOpened(sw, getWindowsLastOpened())

	log.Printf("[software] collected: registry=%d store=%d extensions=%d total=%d (complete=%v)",
		len(registry), len(storeApps), extCount, len(sw), registryOK)
	return sw, registryOK
}

// getWindowsSoftware enumerates installed programs from the registry uninstall
// keys: the machine-wide HKLM hives plus every loaded per-user hive under
// HKEY_USERS. As the SYSTEM service, reading per-user hives directly is the only
// way to see per-user installs (Chrome, VS Code, Slack, …) — the service
// account's own HKCU is empty.
func (s *SoftwareService) getWindowsSoftware() ([]SoftwareInfo, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), collectCmdTimeout)
	defer cancel()

	// Single quotes only (no embedded double quotes / $()-in-string) so the script
	// survives argument escaping intact. Per-user paths are built by concatenating
	// each loaded hive's PSPath with a single-quoted suffix.
	const registryQuery = `$paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
$paths += Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' } | ForEach-Object { $_.PSPath + '\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; $_.PSPath + '\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' }
Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName} | Select-Object @{N='Name';E={$_.DisplayName}},@{N='Version';E={$_.DisplayVersion}},@{N='InstallLocation';E={$_.InstallLocation}},@{N='InstallDate';E={$_.InstallDate}} | Sort-Object Name -Unique | ConvertTo-Json`
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

// getWindowsStoreApps enumerates non-system Microsoft Store (Appx) packages.
// It prefers -AllUsers (so the SYSTEM service sees every user's apps), falling
// back to the current user's packages when not elevated (e.g. the CLI path).
func (s *SoftwareService) getWindowsStoreApps() ([]SoftwareInfo, bool) {
	if items, ok := s.queryAppxPackages(true); ok {
		return items, true
	}
	return s.queryAppxPackages(false)
}

// queryAppxPackages runs Get-AppxPackage with or without -AllUsers and parses
// the result. A failed -AllUsers attempt (insufficient privilege) returns
// ok=false so the caller can retry without it.
func (s *SoftwareService) queryAppxPackages(allUsers bool) ([]SoftwareInfo, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), collectCmdTimeout)
	defer cancel()

	enumerator := "Get-AppxPackage"
	if allUsers {
		enumerator += " -AllUsers"
	}
	query := enumerator + ` | Where-Object {$_.SignatureKind -ne 'System'} | Select-Object @{N='Name';E={$_.Name}},@{N='Version';E={$_.Version}},@{N='InstallLocation';E={$_.InstallLocation}} | Sort-Object Name -Unique | ConvertTo-Json`
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", query)
	output, err := cmd.Output()
	if err != nil {
		if !allUsers {
			log.Printf("software: Get-AppxPackage failed: %v", err)
		}
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
