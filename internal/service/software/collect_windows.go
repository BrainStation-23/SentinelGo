package software

import (
	"context"
	"encoding/json"
	"log"
	"math"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"sentinelgo/internal/binpath"
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
	// each loaded hive's PSPath with a single-quoted suffix. Wow64 marks keys
	// under Wow6432Node, i.e. 32-bit programs on a 64-bit OS.
	const registryQuery = `$paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
$paths += Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' } | ForEach-Object { $_.PSPath + '\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; $_.PSPath + '\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' }
Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName} | Select-Object @{N='Name';E={$_.DisplayName}},@{N='Version';E={$_.DisplayVersion}},@{N='InstallLocation';E={$_.InstallLocation}},@{N='InstallDate';E={$_.InstallDate}},@{N='Publisher';E={$_.Publisher}},@{N='EstimatedSize';E={$_.EstimatedSize}},@{N='Wow64';E={$_.PSPath -match 'Wow6432Node'}} | Sort-Object Name -Unique | ConvertTo-Json`
	cmd := exec.CommandContext(ctx, binpath.Resolve("powershell"), "-NoProfile", "-Command", registryQuery)
	output, err := cmd.Output()
	if err != nil {
		log.Printf("software: registry uninstall query failed: %v", err)
		return nil, false
	}

	var result []SoftwareInfo
	ok := parsePowerShellOutput(output, &result, sourcePrograms)
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
//
// Get-AppxPackage has no install date; each package version is installed into
// its own folder, so the folder's creation time stands in for it. Architecture
// is an enum that ConvertTo-Json would render as a number, hence ToString().
func (s *SoftwareService) queryAppxPackages(allUsers bool) ([]SoftwareInfo, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), collectCmdTimeout)
	defer cancel()

	enumerator := "Get-AppxPackage"
	if allUsers {
		enumerator += " -AllUsers"
	}
	query := enumerator + ` | Where-Object {$_.SignatureKind -ne 'System'} | Select-Object @{N='Name';E={$_.Name}},@{N='Version';E={$_.Version}},@{N='InstallLocation';E={$_.InstallLocation}},@{N='Publisher';E={$_.Publisher}},@{N='Architecture';E={$_.Architecture.ToString()}},@{N='InstallDate';E={if ($_.InstallLocation) { $d = (Get-Item -LiteralPath $_.InstallLocation -ErrorAction SilentlyContinue).CreationTimeUtc; if ($d) { $d.ToString('o') } }}} | Sort-Object Name -Unique | ConvertTo-Json`
	cmd := exec.CommandContext(ctx, binpath.Resolve("powershell"), "-NoProfile", "-Command", query)
	output, err := cmd.Output()
	if err != nil {
		if !allUsers {
			log.Printf("software: Get-AppxPackage failed: %v", err)
		}
		return nil, false
	}
	var result []SoftwareInfo
	ok := parsePowerShellOutput(output, &result, sourceMicrosoftStore)
	return result, ok
}

// windowsOSArch returns the OS architecture as the agent sees it. A var so tests
// can fix it.
var windowsOSArch = func() string {
	// A 32-bit process on a 64-bit OS sees x86 in PROCESSOR_ARCHITECTURE and the
	// real architecture in PROCESSOR_ARCHITEW6432.
	if a := os.Getenv("PROCESSOR_ARCHITEW6432"); a != "" {
		return a
	}
	return os.Getenv("PROCESSOR_ARCHITECTURE")
}

// registryArch derives a program's architecture from the registry view its
// uninstall key lives in. Wow6432Node holds 32-bit programs. The native view on
// x64 holds 64-bit programs, but on ARM64 it holds both x64 and ARM64 programs,
// so it is left out there.
func registryArch(wow64 bool, osArch string) string {
	if wow64 {
		return "x86"
	}
	switch a := normalizeArch(osArch); a {
	case "x64", "x86":
		return a
	}
	return ""
}

// guidCN matches the GUID common name the Store gives to third-party publishers.
var guidCN = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

// appxPublisherName extracts a readable name from an Appx publisher
// distinguished name such as "CN=Microsoft Corporation, O=Microsoft
// Corporation, L=Redmond, S=Washington, C=US". O= is preferred, then CN=
// unless it is a bare GUID. Values with quoted commas are rare and only lose
// their tail.
func appxPublisherName(dn string) string {
	var cn, o string
	for _, part := range strings.Split(dn, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(strings.Trim(strings.TrimSpace(v), `"`))
		switch strings.ToUpper(strings.TrimSpace(k)) {
		case "O":
			if o == "" {
				o = v
			}
		case "CN":
			if cn == "" {
				cn = v
			}
		}
	}
	name := o
	if name == "" {
		name = cn
	}
	if guidCN.MatchString(name) {
		return ""
	}
	return name
}

// parseWindowsInstallDate parses the registry InstallDate (yyyyMMdd) or the
// round-trip ("o") timestamp the Appx query emits, returning RFC 3339 or "".
func parseWindowsInstallDate(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if t, err := time.Parse("20060102", s); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	return ""
}

// parsePowerShellOutput parses a ConvertTo-Json software list into SoftwareInfo entries.
// Returns false when the output could not be parsed as JSON.
func parsePowerShellOutput(output []byte, software *[]SoftwareInfo, source string) bool {
	var psOutput []map[string]any
	if err := json.Unmarshal(output, &psOutput); err != nil {
		var single map[string]any
		if json.Unmarshal(output, &single) != nil {
			return false
		}
		psOutput = []map[string]any{single}
	}

	osArch := windowsOSArch()
	for _, item := range psOutput {
		name, ok := item["Name"].(string)
		if !ok {
			continue
		}
		version, _ := item["Version"].(string)
		installLocation, _ := item["InstallLocation"].(string)
		rawDate, _ := item["InstallDate"].(string)
		publisher, _ := item["Publisher"].(string)

		installDate := parseWindowsInstallDate(rawDate)
		firstSeen := installDate
		if firstSeen == "" {
			firstSeen = time.Now().UTC().Format(time.RFC3339)
		}
		sw := SoftwareInfo{
			Name:             name,
			InstalledVersion: version,
			FilePath:         installLocation,
			Source:           source,
			Type:             source,
			FirstSeenAt:      firstSeen,
			InstallDate:      installDate,
			Publisher:        stripEmail(publisher),
		}
		// EstimatedSize is a DWORD in KB; anything larger is not a real value.
		if kb, ok := item["EstimatedSize"].(float64); ok && kb > 0 && kb <= math.MaxUint32 {
			sw.SizeBytes = int64(kb) * 1024
		}
		if source == sourceMicrosoftStore {
			sw.Publisher = appxPublisherName(publisher)
			arch, _ := item["Architecture"].(string)
			sw.Architecture = normalizeArch(arch)
		} else {
			wow64, _ := item["Wow64"].(bool)
			sw.Architecture = registryArch(wow64, osArch)
		}
		*software = append(*software, sw)
	}
	return true
}

// chromeExtDirGlobs returns Chrome extension directory glob patterns on Windows.
func chromeExtDirGlobs(home string) []string {
	return browserExtDirs(home,
		`AppData\Local\Google\Chrome\User Data\Default\Extensions`,
		`AppData\Local\Google\Chrome\User Data\Profile *\Extensions`)
}

// edgeExtDirGlobs returns Edge extension directory glob patterns on Windows.
func edgeExtDirGlobs(home string) []string {
	return browserExtDirs(home,
		`AppData\Local\Microsoft\Edge\User Data\Default\Extensions`,
		`AppData\Local\Microsoft\Edge\User Data\Profile *\Extensions`)
}

// braveExtDirGlobs returns Brave extension directory glob patterns on Windows.
func braveExtDirGlobs(home string) []string {
	return browserExtDirs(home,
		`AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Extensions`,
		`AppData\Local\BraveSoftware\Brave-Browser\User Data\Profile *\Extensions`)
}

// firefoxProfileGlobs returns Firefox profile directory glob patterns on Windows.
func firefoxProfileGlobs(home string) []string {
	return browserExtDirs(home, `AppData\Roaming\Mozilla\Firefox\Profiles\*`)
}
