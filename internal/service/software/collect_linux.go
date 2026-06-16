package software

import (
	"context"
	"log"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// platformSoftware collects currently installed software on Linux. It returns
// the aggregated list and whether the scan was complete (a system package
// manager — dpkg or rpm — succeeded). snap/flatpak are supplementary, and
// per-user flatpaks are not fully captured when running as root (known
// limitation). LastOpened is not collected for Linux packages.
func (s *SoftwareService) platformSoftware() ([]SoftwareInfo, bool) {
	var sw []SoftwareInfo

	deb, debOK := s.getDebPackages()
	sw = append(sw, deb...)
	rpm, rpmOK := s.getRPMPackages()
	sw = append(sw, rpm...)
	snap, _ := s.getSnapPackages()
	sw = append(sw, snap...)
	flatpak, _ := s.getFlatpakPackages()
	sw = append(sw, flatpak...)

	extStart := len(sw)
	s.appendExtensions(&sw)
	extCount := len(sw) - extStart

	complete := debOK || rpmOK
	log.Printf("[software] collected: deb=%d rpm=%d snap=%d flatpak=%d extensions=%d total=%d (complete=%v)",
		len(deb), len(rpm), len(snap), len(flatpak), extCount, len(sw), complete)
	return sw, complete
}

func (s *SoftwareService) getDebPackages() ([]SoftwareInfo, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), collectCmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Package},${Version},${Installed-Size}")
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
	ctx, cancel := context.WithTimeout(context.Background(), collectCmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "rpm", "-qa", "--queryformat", "%{NAME} %{VERSION} %{SIZE} %{INSTALLTIME}\n")
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
	ctx, cancel := context.WithTimeout(context.Background(), collectCmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "snap", "list", "--color=never")
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
	ctx, cancel := context.WithTimeout(context.Background(), collectCmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "flatpak", "list", "--columns=application,name,version,origin")
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
		*packages = append(*packages, SoftwareInfo{
			Name:             parts[0],
			InstalledVersion: parts[1],
			SoftwarePackage:  parts[0],
			Source:           "deb_packages",
			Type:             "deb_packages",
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
		firstSeen := ""
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
			FirstSeenAt:      firstSeen,
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
		*packages = append(*packages, SoftwareInfo{
			Name:             parts[0],
			InstalledVersion: parts[1],
			SoftwarePackage:  parts[0],
			Source:           "snap_packages",
			Type:             "snap_packages",
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
		*packages = append(*packages, SoftwareInfo{
			Name:             parts[1],
			InstalledVersion: parts[2],
			SoftwarePackage:  parts[0],
			Source:           "flatpak_packages",
			Type:             "flatpak_packages",
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
