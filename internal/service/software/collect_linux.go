package software

import (
	"log"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// platformSoftware collects installed software on Linux along with the set of
// source categories that were authoritatively scanned this cycle. A package
// manager that is not installed (e.g. rpm on Debian) reports failure and is left
// out of scanned, so its absence never demotes another source's rows.
//
// LastOpened is not yet collected for Linux packages (gap; tracked for follow-up).
func (s *SoftwareService) platformSoftware() ([]SoftwareInfo, map[string]bool) {
	scanned := make(map[string]bool)
	var sw []SoftwareInfo

	if items, ok := s.getDebPackages(); ok {
		sw = append(sw, items...)
		scanned["deb_packages"] = true
	}
	if items, ok := s.getRPMPackages(); ok {
		sw = append(sw, items...)
		scanned["rpm_packages"] = true
	}
	if items, ok := s.getSnapPackages(); ok {
		sw = append(sw, items...)
		scanned["snap_packages"] = true
	}
	if items, ok := s.getFlatpakPackages(); ok {
		sw = append(sw, items...)
		scanned["flatpak_packages"] = true
	}
	s.appendExtensions(&sw, scanned)

	return sw, scanned
}

func (s *SoftwareService) getDebPackages() ([]SoftwareInfo, bool) {
	cmd := exec.Command("dpkg-query", "-W", "-f=${Package},${Version},${Installed-Size}")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("software: dpkg-query failed: %v", err)
		return nil, false
	}
	var packages []SoftwareInfo
	parseDebPackages(output, &packages)
	return packages, true
}

func (s *SoftwareService) getRPMPackages() ([]SoftwareInfo, bool) {
	cmd := exec.Command("rpm", "-qa", "--queryformat", "%{NAME} %{VERSION} %{SIZE} %{INSTALLTIME}\n")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("software: rpm -qa failed: %v", err)
		return nil, false
	}
	var packages []SoftwareInfo
	parseRPMPackages(output, &packages)
	return packages, true
}

func (s *SoftwareService) getSnapPackages() ([]SoftwareInfo, bool) {
	cmd := exec.Command("snap", "list", "--color=never")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("software: snap list failed: %v", err)
		return nil, false
	}
	var packages []SoftwareInfo
	parseSnapPackages(output, &packages)
	return packages, true
}

func (s *SoftwareService) getFlatpakPackages() ([]SoftwareInfo, bool) {
	cmd := exec.Command("flatpak", "list", "--columns=application,name,version,origin")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("software: flatpak list failed: %v", err)
		return nil, false
	}
	var packages []SoftwareInfo
	parseFlatpakPackages(output, &packages)
	return packages, true
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
		firstSeen := now
		if len(parts) >= 4 {
			if ts, err := strconv.ParseInt(parts[3], 10, 64); err == nil && ts > 0 {
				firstSeen = time.Unix(ts, 0).UTC().Format(time.RFC3339)
			}
		}
		*packages = append(*packages, SoftwareInfo{
			Name:             parts[0],
			InstalledVersion: parts[1],
			SoftwarePackage:  parts[0],
			Source:           "rpm_packages",
			Type:             "rpm_packages",
			Status:           "installed",
			FirstSeenAt:      firstSeen,
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
