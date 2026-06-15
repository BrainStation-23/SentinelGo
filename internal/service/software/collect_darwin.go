package software

import (
	"encoding/json"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const mdlsBatchSize = 200

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
		out, err := exec.Command("mdls", args...).Output()
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

// platformSoftware collects installed software on macOS.
func (s *SoftwareService) platformSoftware() []SoftwareInfo {
	var sw []SoftwareInfo
	sw = append(sw, s.getMacApplications()...)
	sw = append(sw, s.getHomebrewPackages()...)
	sw = append(sw, s.getHomebrewCaskPackages()...)
	sw = append(sw, s.getChromeExtensions()...)
	sw = append(sw, s.getFirefoxExtensions()...)
	sw = append(sw, s.getEdgeExtensions()...)
	sw = append(sw, s.getBraveExtensions()...)
	return sw
}

func (s *SoftwareService) getMacApplications() []SoftwareInfo {
	cmd := exec.Command("system_profiler", "SPApplicationsDataType", "-json")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("software: system_profiler SPApplicationsDataType failed: %v", err)
		return nil
	}
	var applications []SoftwareInfo
	parseSystemProfilerApps(output, &applications)

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

	return applications
}

func (s *SoftwareService) getHomebrewPackages() []SoftwareInfo {
	cmd := exec.Command("brew", "list", "--versions")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("software: brew list --versions failed: %v", err)
		return nil
	}
	var packages []SoftwareInfo
	parseHomebrewPackages(output, &packages, "homebrew")
	return packages
}

func (s *SoftwareService) getHomebrewCaskPackages() []SoftwareInfo {
	cmd := exec.Command("brew", "list", "--cask", "--versions")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("software: brew list --cask --versions failed: %v", err)
		return nil
	}
	var packages []SoftwareInfo
	parseHomebrewPackages(output, &packages, "homebrew_cask")
	return packages
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

func parseSystemProfilerApps(output []byte, applications *[]SoftwareInfo) {
	var spOut systemProfilerOutput
	if err := json.Unmarshal(output, &spOut); err != nil {
		return
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
		now := time.Now().Format(time.RFC3339)
		firstSeen := now
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
			Status:           "installed",
			FirstSeenAt:      firstSeen,
			LastSeenAt:       now,
			IsActive:         true,
		})
	}
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
		now := time.Now().Format(time.RFC3339)
		*packages = append(*packages, SoftwareInfo{
			Name:             parts[0],
			InstalledVersion: parts[1],
			SoftwarePackage:  parts[0],
			Source:           source,
			Type:             source,
			Status:           "installed",
			FirstSeenAt:      now,
			LastSeenAt:       now,
			IsActive:         true,
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
