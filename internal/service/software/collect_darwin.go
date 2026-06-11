package software

import (
	"encoding/json"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

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
