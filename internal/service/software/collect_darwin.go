package software

import (
	"context"
	"encoding/json"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const mdlsBatchSize = 200

// runCollectCmd runs an enumeration command under collectCmdTimeout so a hung tool
// (e.g. a stalled system_profiler) errors out instead of blocking the sync goroutine.
func runCollectCmd(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), collectCmdTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

// batchMdlsLastOpened queries Spotlight metadata for the last-used date of a
// set of app paths. Returns a map of path → RFC3339 timestamp. Paths that were
// never opened or whose metadata is unavailable are omitted from the map.
func batchMdlsLastOpened(paths []string) map[string]string {
	result := make(map[string]string, len(paths))
	for i := 0; i < len(paths); i += mdlsBatchSize {
		end := i + mdlsBatchSize
		if end > len(paths) {
			end = len(paths)
		}
		batch := paths[i:end]
		args := append([]string{"-name", "kMDItemLastUsedDate"}, batch...)
		out, err := runCollectCmd("mdls", args...)
		if err != nil {
			log.Printf("software: mdls batch failed: %v", err)
			continue
		}
		parseMdlsOutput(string(out), batch, result)
	}
	return result
}

// parseMdlsOutput parses the output of `mdls -name kMDItemLastUsedDate path1 path2 ...`.
// Each file block starts with the path followed by a colon, then the attribute line.
func parseMdlsOutput(output string, paths []string, result map[string]string) {
	// Build a quick lookup so we can match path headers back to original paths.
	pathSet := make(map[string]string, len(paths))
	for _, p := range paths {
		pathSet[p+":"] = p
	}

	var currentPath string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Path header: "/Applications/Safari.app:"
		if strings.HasSuffix(line, ":") {
			if orig, ok := pathSet[line]; ok {
				currentPath = orig
			} else {
				currentPath = ""
			}
			continue
		}
		if currentPath == "" {
			continue
		}
		// Attribute line: "kMDItemLastUsedDate = 2025-06-10 08:42:11 +0000" or "(null)"
		if !strings.HasPrefix(line, "kMDItemLastUsedDate") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		val := strings.TrimSpace(parts[1])
		if val == "(null)" || val == "" {
			continue
		}
		t, err := time.Parse("2006-01-02 15:04:05 +0000", val)
		if err != nil {
			continue
		}
		result[currentPath] = t.UTC().Format(time.RFC3339)
	}
}

// platformSoftware collects currently installed software on macOS. It returns
// the aggregated list and whether the scan was complete (system_profiler — the
// bulk source — succeeded). brew is per-user and not fully captured when running
// as root (known limitation).
func (s *SoftwareService) platformSoftware() ([]SoftwareInfo, bool) {
	var sw []SoftwareInfo

	apps, appsOK := s.getMacApplications()
	sw = append(sw, apps...)
	brew, _ := s.getHomebrewPackages()
	sw = append(sw, brew...)
	cask, _ := s.getHomebrewCaskPackages()
	sw = append(sw, cask...)

	extStart := len(sw)
	s.appendExtensions(&sw)
	extCount := len(sw) - extStart

	log.Printf("[software] collected: apps=%d brew=%d cask=%d extensions=%d total=%d (complete=%v)",
		len(apps), len(brew), len(cask), extCount, len(sw), appsOK)
	return sw, appsOK
}

func (s *SoftwareService) getMacApplications() ([]SoftwareInfo, bool) {
	output, err := runCollectCmd("system_profiler", "SPApplicationsDataType", "-json")
	if err != nil {
		log.Printf("software: system_profiler SPApplicationsDataType failed: %v", err)
		return nil, false
	}
	var applications []SoftwareInfo
	if !parseSystemProfilerApps(output, &applications) {
		return nil, false
	}

	// Collect paths to batch-query last-opened metadata.
	paths := make([]string, 0, len(applications))
	for _, app := range applications {
		if app.FilePath != "" {
			paths = append(paths, app.FilePath)
		}
	}
	if len(paths) > 0 {
		lastOpened := batchMdlsLastOpened(paths)
		for i := range applications {
			if ts, ok := lastOpened[applications[i].FilePath]; ok {
				applications[i].LastOpened = ts
			}
		}
	}

	return applications, true
}

func (s *SoftwareService) getHomebrewPackages() ([]SoftwareInfo, bool) {
	output, err := runCollectCmd("brew", "list", "--versions")
	if err != nil {
		log.Printf("software: brew list --versions failed: %v", err)
		return nil, false
	}
	var packages []SoftwareInfo
	parseHomebrewPackages(output, &packages, "homebrew")
	return packages, true
}

func (s *SoftwareService) getHomebrewCaskPackages() ([]SoftwareInfo, bool) {
	output, err := runCollectCmd("brew", "list", "--cask", "--versions")
	if err != nil {
		log.Printf("software: brew list --cask --versions failed: %v", err)
		return nil, false
	}
	var packages []SoftwareInfo
	parseHomebrewPackages(output, &packages, "homebrew_cask")
	return packages, true
}

type systemProfilerOutput struct {
	SPApplicationsDataType []struct {
		Name         string `json:"_name"`
		Version      string `json:"version"`
		Path         string `json:"path"`
		ObtainedFrom string `json:"obtained_from"`
		LastModified string `json:"lastModified"`
	} `json:"SPApplicationsDataType"`
}

// parseSystemProfilerApps parses system_profiler JSON into applications. It
// returns false when the output is not valid JSON (a failed query), which the
// caller treats as "source not scanned" so the catalog is preserved rather than
// reconciled against an empty result.
func parseSystemProfilerApps(output []byte, applications *[]SoftwareInfo) bool {
	var spOut systemProfilerOutput
	if err := json.Unmarshal(output, &spOut); err != nil {
		return false
	}
	for _, app := range spOut.SPApplicationsDataType {
		if app.Name == "" {
			continue
		}
		source := "applications"
		appStoreApp := ""
		if app.ObtainedFrom == "mac_app_store" {
			source = "app_store"
			appStoreApp = "true"
		}
		firstSeen := time.Now().UTC().Format(time.RFC3339)
		if app.LastModified != "" {
			firstSeen = app.LastModified
		}
		*applications = append(*applications, SoftwareInfo{
			Name:             app.Name,
			DisplayName:      app.Name,
			InstalledVersion: app.Version,
			FilePath:         app.Path,
			AppStoreApp:      appStoreApp,
			Source:           source,
			Type:             source,
			FirstSeenAt:      firstSeen,
		})
	}
	return true
}

func parseHomebrewPackages(output []byte, packages *[]SoftwareInfo, source string) {
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		*packages = append(*packages, SoftwareInfo{
			Name:             parts[0],
			InstalledVersion: parts[1],
			SoftwarePackage:  parts[0],
			Source:           source,
			Type:             source,
		})
	}
}

// chromeExtDirGlobs returns Chrome extension directory glob patterns on macOS.
func chromeExtDirGlobs(home string) []string {
	return []string{
		filepath.Join(home, "Library/Application Support/Google/Chrome/Default/Extensions"),
		filepath.Join(home, "Library/Application Support/Google/Chrome/Profile */Extensions"),
	}
}

// edgeExtDirGlobs returns Edge extension directory glob patterns on macOS.
func edgeExtDirGlobs(home string) []string {
	return []string{
		filepath.Join(home, "Library/Application Support/Microsoft Edge/Default/Extensions"),
		filepath.Join(home, "Library/Application Support/Microsoft Edge/Profile */Extensions"),
	}
}

// braveExtDirGlobs returns Brave extension directory glob patterns on macOS.
func braveExtDirGlobs(home string) []string {
	return []string{
		filepath.Join(home, "Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions"),
		filepath.Join(home, "Library/Application Support/BraveSoftware/Brave-Browser/Profile */Extensions"),
	}
}

// firefoxProfileGlobs returns Firefox profile directory glob patterns on macOS.
func firefoxProfileGlobs(home string) []string {
	return []string{
		filepath.Join(home, "Library/Application Support/Firefox/Profiles/*"),
	}
}
