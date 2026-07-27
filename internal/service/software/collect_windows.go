package software

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName} | Select-Object @{N='Name';E={$_.DisplayName}},@{N='Version';E={$_.DisplayVersion}},@{N='InstallLocation';E={$_.InstallLocation}},@{N='InstallDate';E={$_.InstallDate}},@{N='Publisher';E={$_.Publisher}} | Sort-Object Name -Unique | ConvertTo-Json`
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
		// Some registry InstallLocation values are wrapped in double-quotes
		// (e.g. `"C:\Program Files\App"`) — strip them so os.Stat works correctly.
		installLocation = strings.Trim(installLocation, `"`)
		// Publisher is populated for registry ("programs") entries — it comes from
		// the DisplayPublisher / Publisher registry value selected by the PS query.
		// Store apps and extensions do not carry this field, so it stays empty.
		publisher, _ := item["Publisher"].(string)

		now := time.Now().UTC().Format(time.RFC3339)
		firstSeen := now
		if installDate, _ := item["InstallDate"].(string); installDate != "" {
			if t, err := time.Parse("20060102", installDate); err == nil {
				firstSeen = t.UTC().Format(time.RFC3339)
			}
		}

		// Resolve the FilePath to a hashable file.
		// InstallLocation from the registry is typically a directory
		// (e.g. "C:\Program Files\Google\Chrome\Application\"). We try to
		// find the primary executable so EnrichWithHash can compute a
		// meaningful hash. If resolution fails we store the original path
		// and let EnrichWithHash skip it gracefully.
		resolvedPath := resolveWindowsExePath(installLocation)

		*software = append(*software, SoftwareInfo{
			Name:             name,
			InstalledVersion: version,
			FilePath:         resolvedPath,
			Source:           source,
			Type:             source,
			FirstSeenAt:      firstSeen,
			Publisher:        publisher,
		})
	}
	return true
}

// resolveWindowsExePath takes an InstallLocation string from the registry and
// returns the best path for hashing:
//
//   - Empty string                → returned as-is (EnrichWithHash will skip)
//   - Already a .exe file         → returned as-is
//   - WindowsApps\ directory      → returned as-is with empty string so
//     EnrichWithHash skips it; these paths are ACL-protected and always
//     fail with "Incorrect function" for non-admin processes
//   - Any other directory         → we look for a single .exe inside the
//     directory (non-recursive) whose stem matches the last component of
//     the directory name (e.g. "chrome.exe" inside "…\Chrome\Application\").
//     If exactly one candidate is found it is returned; otherwise the
//     directory path itself is returned and EnrichWithHash will skip it.
func resolveWindowsExePath(installLocation string) string {
	if installLocation == "" {
		return ""
	}

	// Already points at a file — use it directly.
	info, err := os.Stat(installLocation)
	if err != nil {
		// Path does not exist or is inaccessible; return as-is so
		// EnrichWithHash skips it cleanly.
		return installLocation
	}
	if !info.IsDir() {
		return installLocation
	}

	// WindowsApps\ is always ACL-protected at the directory level for
	// non-admin processes (returns "Incorrect function" / ERROR_INVALID_FUNCTION
	// on ReadDir). Clear the path so EnrichWithHash skips it silently instead
	// of logging a confusing per-app error on every cycle.
	normalized := strings.ToLower(filepath.ToSlash(installLocation))
	if strings.Contains(normalized, "/windowsapps/") ||
		strings.Contains(normalized, `\windowsapps\`) {
		return ""
	}

	// It is a regular directory — look for .exe files directly inside it.
	entries, err := os.ReadDir(installLocation)
	if err != nil {
		return installLocation
	}

	// Collect all .exe files in the directory (non-recursive).
	var exes []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.EqualFold(filepath.Ext(e.Name()), ".exe") {
			exes = append(exes, filepath.Join(installLocation, e.Name()))
		}
	}

	switch len(exes) {
	case 0:
		// No .exe in the top level. Some apps put their binary one level
		// deeper; return empty so EnrichWithHash skips quietly.
		return ""
	case 1:
		// Exactly one exe — unambiguous.
		return exes[0]
	default:
		// Multiple exes. Prefer one whose stem matches the last meaningful
		// directory component (e.g. "chrome" in "…\Chrome\Application\").
		dir := filepath.Clean(installLocation)
		// Walk up to find a non-trivially-named component.
		components := strings.Split(filepath.ToSlash(dir), "/")
		for i := len(components) - 1; i >= 0; i-- {
			part := strings.ToLower(components[i])
			if part == "" || part == "application" || part == "bin" || part == "app" {
				continue
			}
			for _, exe := range exes {
				stem := strings.ToLower(strings.TrimSuffix(filepath.Base(exe), ".exe"))
				if stem == part || strings.HasPrefix(part, stem) || strings.HasPrefix(stem, part) {
					return exe
				}
			}
			break
		}
		// No name match — return the first exe alphabetically.
		return exes[0]
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
