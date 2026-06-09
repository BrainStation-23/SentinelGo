package software

import (
	"log"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// platformSoftware collects installed software on Linux.
func (s *SoftwareService) platformSoftware() []SoftwareInfo {
	var sw []SoftwareInfo
	sw = append(sw, s.getDebPackages()...)
	sw = append(sw, s.getRPMPackages()...)
	sw = append(sw, s.getSnapPackages()...)
	sw = append(sw, s.getFlatpakPackages()...)
	sw = append(sw, s.getChromeExtensions()...)
	sw = append(sw, s.getFirefoxExtensions()...)
	sw = append(sw, s.getEdgeExtensions()...)
	sw = append(sw, s.getBraveExtensions()...)
	return sw
}

func (s *SoftwareService) getDebPackages() []SoftwareInfo {
	cmd := exec.Command("dpkg-query", "-W", "-f=${Package},${Version},${Installed-Size}")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("software: dpkg-query failed: %v", err)
		return nil
	}
	var packages []SoftwareInfo
	parseDebPackages(output, &packages)
	return packages
}

func (s *SoftwareService) getRPMPackages() []SoftwareInfo {
	cmd := exec.Command("rpm", "-qa", "--queryformat", "%{NAME} %{VERSION} %{SIZE}")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("software: rpm -qa failed: %v", err)
		return nil
	}
	var packages []SoftwareInfo
	parseRPMPackages(output, &packages)
	return packages
}

func (s *SoftwareService) getSnapPackages() []SoftwareInfo {
	cmd := exec.Command("snap", "list", "--color=never")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("software: snap list failed: %v", err)
		return nil
	}
	var packages []SoftwareInfo
	parseSnapPackages(output, &packages)
	return packages
}

func (s *SoftwareService) getFlatpakPackages() []SoftwareInfo {
	cmd := exec.Command("flatpak", "list", "--columns=application,name,version,origin")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("software: flatpak list failed: %v", err)
		return nil
	}
	var packages []SoftwareInfo
	parseFlatpakPackages(output, &packages)
	return packages
}

func parseDebPackages(output []byte, packages *[]SoftwareInfo) {
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}
		now := time.Now().Format(time.RFC3339)
		*packages = append(*packages, SoftwareInfo{
			Name:             parts[0],
			InstalledVersion: parts[1],
			SoftwarePackage:  parts[0],
			Source:           "deb_packages",
			Type:             "deb_packages",
			Status:           "installed",
			FirstSeenAt:      now,
			LastSeenAt:       now,
			IsActive:         true,
		})
	}
}

func parseRPMPackages(output []byte, packages *[]SoftwareInfo) {
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
			Source:           "rpm_packages",
			Type:             "rpm_packages",
			Status:           "installed",
			FirstSeenAt:      now,
			LastSeenAt:       now,
			IsActive:         true,
		})
	}
}

func parseSnapPackages(output []byte, packages *[]SoftwareInfo) {
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Name") {
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
			Source:           "snap_packages",
			Type:             "snap_packages",
			Status:           "installed",
			FirstSeenAt:      now,
			LastSeenAt:       now,
			IsActive:         true,
		})
	}
}

func parseFlatpakPackages(output []byte, packages *[]SoftwareInfo) {
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "application") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		now := time.Now().Format(time.RFC3339)
		*packages = append(*packages, SoftwareInfo{
			Name:             parts[1],
			InstalledVersion: parts[2],
			SoftwarePackage:  parts[0],
			Source:           "flatpak_packages",
			Type:             "flatpak_packages",
			Status:           "installed",
			FirstSeenAt:      now,
			LastSeenAt:       now,
			IsActive:         true,
		})
	}
}

// chromeExtDirGlobs returns Chrome extension directory glob patterns on Linux.
func chromeExtDirGlobs(home string) []string {
	return []string{
		filepath.Join(home, ".config/google-chrome/Default/Extensions"),
		filepath.Join(home, ".config/google-chrome/Profile */Extensions"),
	}
}

// edgeExtDirGlobs returns Edge extension directory glob patterns on Linux.
func edgeExtDirGlobs(home string) []string {
	return []string{
		filepath.Join(home, ".config/microsoft-edge/Default/Extensions"),
		filepath.Join(home, ".config/microsoft-edge/Profile */Extensions"),
	}
}

// braveExtDirGlobs returns Brave extension directory glob patterns on Linux.
func braveExtDirGlobs(home string) []string {
	return []string{
		filepath.Join(home, ".config/BraveSoftware/Brave-Browser/Default/Extensions"),
		filepath.Join(home, ".config/BraveSoftware/Brave-Browser/Profile */Extensions"),
	}
}

// firefoxProfileGlobs returns Firefox profile directory glob patterns on Linux.
func firefoxProfileGlobs(home string) []string {
	return []string{
		filepath.Join(home, ".mozilla/firefox/*"),
	}
}
