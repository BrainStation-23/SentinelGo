package software

import (
	"context"
	"log"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"sentinelgo/internal/binpath"
)

// dpkgInfoDir holds each installed package's file list (<pkg>.list); its mtime
// is the package's install (or last upgrade) time. A var so tests can point it
// at a temp dir.
var dpkgInfoDir = "/var/lib/dpkg/info"

// snapBlobDir holds the .snap file of every installed revision. A var so tests
// can point it at a temp dir.
var snapBlobDir = "/var/lib/snapd/snaps"

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

	// Tab-separated because Maintainer contains spaces and sometimes commas;
	// dpkg-query expands the \t and \n escapes itself. The status column lets
	// the parser drop removed packages dpkg still lists for their config files.
	// #nosec G204 - binpath.Resolve returns a fixed, verified absolute path or the literal name; not attacker input
	cmd := exec.CommandContext(ctx, binpath.Resolve("dpkg-query"), "-W",
		`-f=${db:Status-Abbrev}\t${Package}\t${Version}\t${Installed-Size}\t${Architecture}\t${Maintainer}\n`)
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

	// Tab-separated because VENDOR contains spaces ("Red Hat, Inc.").
	// #nosec G204 - binpath.Resolve returns a fixed, verified absolute path or the literal name; not attacker input
	cmd := exec.CommandContext(ctx, binpath.Resolve("rpm"), "-qa", "--queryformat",
		`%{NAME}\t%{VERSION}\t%{SIZE}\t%{INSTALLTIME}\t%{ARCH}\t%{VENDOR}\n`)
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

	// #nosec G204 - binpath.Resolve returns a fixed, verified absolute path or the literal name; not attacker input
	cmd := exec.CommandContext(ctx, binpath.Resolve("snap"), "list", "--color=never", "--unicode=never")
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

	// #nosec G204 - binpath.Resolve returns a fixed, verified absolute path or the literal name; not attacker input
	cmd := exec.CommandContext(ctx, binpath.Resolve("flatpak"), "list", "--columns=application,name,version,origin,arch")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("software: flatpak list failed: %v", err)
		return nil, false
	}
	var packages []SoftwareInfo
	parseFlatpakPackages(output, &packages)
	return packages, true
}

// splitColumns splits a tab-separated line, falling back to splitWithout when
// the line has no tab (the older formats these parsers also accept).
func splitColumns(line string, splitWithout func(string) []string) []string {
	if !strings.Contains(line, "\t") {
		return splitWithout(line)
	}
	return splitTabs(line)
}

// splitTabs splits line on tabs and trims each column.
func splitTabs(line string) []string {
	parts := strings.Split(line, "\t")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// parseDebPackages parses dpkg-query lines of
// Status-Abbrev<TAB>Package<TAB>Version<TAB>Installed-Size<TAB>Architecture<TAB>Maintainer.
// Only installed packages are kept. The install date is the mtime of the
// package's file list.
func parseDebPackages(output []byte, packages *[]SoftwareInfo) {
	var found []SoftwareInfo
	var rawArchs []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if sw, rawArch, ok := parseDebLine(splitTabs(line)); ok {
			found = append(found, sw)
			rawArchs = append(rawArchs, rawArch)
		}
	}
	qualifyMultiArch(found, rawArchs)
	*packages = append(*packages, found...)
}

// parseDebLine builds the entry for one dpkg-query line split into columns,
// returning the raw dpkg architecture alongside it. ok is false for packages
// that are not installed and for malformed lines.
func parseDebLine(parts []string) (sw SoftwareInfo, rawArch string, ok bool) {
	if len(parts) < 3 || parts[1] == "" || !debInstalled(parts[0]) {
		return SoftwareInfo{}, "", false
	}
	rawArch = column(parts, 4)
	sw = SoftwareInfo{
		Name:             parts[1],
		InstalledVersion: parts[2],
		SoftwarePackage:  parts[1],
		Source:           sourceDebPackages,
		Type:             sourceDebPackages,
		SizeBytes:        kibToBytes(positiveInt(column(parts, 3))),
		Architecture:     normalizeArch(rawArch),
		Publisher:        stripEmail(column(parts, 5)),
		InstallDate:      debInstallDate(parts[1], rawArch),
	}
	return sw, rawArch, true
}

// kibToBytes converts dpkg's Installed-Size (KiB) to bytes, returning 0 for a
// value too large to be real rather than overflowing.
func kibToBytes(kib int64) int64 {
	if kib > math.MaxInt64/1024 {
		return 0
	}
	return kib * 1024
}

// column returns parts[i], or "" when the line has fewer columns.
func column(parts []string, i int) string {
	if i < len(parts) {
		return parts[i]
	}
	return ""
}

// positiveInt parses s as a decimal integer, returning 0 when it is not a
// positive one.
func positiveInt(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// debInstalled reports whether a ${db:Status-Abbrev} value ("ii ", "rc ", …)
// describes a package whose files are on disk. The second letter is the
// package state: n (not installed), c (only config files left) and H (half
// installed) are dropped. Unpacked, half-configured and trigger-pending
// packages are kept, as they are installed in all but configuration.
func debInstalled(status string) bool {
	if len(status) < 2 {
		return false
	}
	switch status[1] {
	case 'i', 'U', 'F', 'W', 't':
		return true
	}
	return false
}

// qualifyMultiArch appends ":<arch>" to the names of packages installed for
// more than one architecture (e.g. libc6 for amd64 and i386, or glibc for
// x86_64 and i686), whose names would otherwise collide in the catalog, which
// is keyed by name and source. rawArchs holds each package's architecture as
// the package manager printed it. Names installed once are left as they are.
func qualifyMultiArch(packages []SoftwareInfo, rawArchs []string) {
	archs := make(map[string]map[string]bool, len(packages))
	for i, p := range packages {
		if archs[p.Name] == nil {
			archs[p.Name] = map[string]bool{}
		}
		archs[p.Name][rawArchs[i]] = true
	}
	for i := range packages {
		if len(archs[packages[i].Name]) > 1 && rawArchs[i] != "" {
			packages[i].Name += ":" + rawArchs[i]
		}
	}
}

// debInstallDate returns the mtime of the package's dpkg file list as RFC 3339,
// or "" when it cannot be read. Multi-arch "same" packages name the list
// <pkg>:<arch>.list, everything else <pkg>.list.
func debInstallDate(pkg, arch string) string {
	if pkg == "" || strings.ContainsAny(pkg+arch, `/\`) {
		return ""
	}
	candidates := []string{pkg + ".list"}
	if arch != "" {
		candidates = append([]string{pkg + ":" + arch + ".list"}, candidates...)
	}
	for _, c := range candidates {
		if fi, err := os.Stat(filepath.Join(dpkgInfoDir, c)); err == nil {
			return fi.ModTime().UTC().Format(time.RFC3339)
		}
	}
	return ""
}

// parseRPMPackages parses rpm lines of
// NAME<TAB>VERSION<TAB>SIZE<TAB>INSTALLTIME<TAB>ARCH<TAB>VENDOR. Whitespace-
// separated lines in the older NAME VERSION SIZE INSTALLTIME format are
// accepted too.
func parseRPMPackages(output []byte, packages *[]SoftwareInfo) {
	var found []SoftwareInfo
	var rawArchs []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if sw, rawArch, ok := parseRPMLine(splitColumns(line, strings.Fields)); ok {
			found = append(found, sw)
			rawArchs = append(rawArchs, rawArch)
		}
	}
	qualifyMultiArch(found, rawArchs)
	*packages = append(*packages, found...)
}

// parseRPMLine builds the entry for one rpm line split into columns, returning
// the raw rpm architecture alongside it. ok is false for malformed lines.
func parseRPMLine(parts []string) (sw SoftwareInfo, rawArch string, ok bool) {
	if len(parts) < 2 || parts[0] == "" {
		return SoftwareInfo{}, "", false
	}
	rawArch = rpmValue(column(parts, 4))
	sw = SoftwareInfo{
		Name:             parts[0],
		InstalledVersion: parts[1],
		SoftwarePackage:  parts[0],
		Source:           sourceRPMPackages,
		Type:             sourceRPMPackages,
		SizeBytes:        positiveInt(column(parts, 2)), // %{SIZE} is in bytes
		Architecture:     normalizeArch(rawArch),
		Publisher:        rpmValue(column(parts, 5)),
	}
	if ts := positiveInt(column(parts, 3)); ts > 0 {
		sw.InstallDate = time.Unix(ts, 0).UTC().Format(time.RFC3339)
		sw.FirstSeenAt = sw.InstallDate
	}
	return sw, rawArch, true
}

// rpmValue maps rpm's "(none)" placeholder for an unset tag to "".
func rpmValue(s string) string {
	if s == "(none)" {
		return ""
	}
	return s
}

// parseSnapPackages parses `snap list` output (Name Version Rev Tracking
// Publisher Notes). The install date and size come from the installed
// revision's .snap file, so the date is when that revision was installed.
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
		sw := SoftwareInfo{
			Name:             parts[0],
			InstalledVersion: parts[1],
			SoftwarePackage:  parts[0],
			Source:           sourceSnapPackages,
			Type:             sourceSnapPackages,
		}
		if len(parts) > 2 {
			sw.InstallDate, sw.SizeBytes = snapRevisionInfo(parts[0], parts[2])
		}
		if len(parts) > 4 {
			sw.Publisher = snapPublisher(parts[4])
		}
		*packages = append(*packages, sw)
	}
}

// snapPublisher strips the verified / starred-developer marks snap appends to a
// publisher ("**" or "*" with --unicode=never, "✓" or "✪" otherwise). "-"
// means the snap has no publisher.
func snapPublisher(p string) string {
	p = strings.TrimRight(p, "*✓✪")
	if p == "-" {
		return ""
	}
	return p
}

// snapRevisionInfo returns the mtime (RFC 3339) and size of the .snap file for
// name at revision rev, or zero values when it cannot be read.
func snapRevisionInfo(name, rev string) (string, int64) {
	if name == "" || rev == "" || strings.ContainsAny(name+rev, `/\`) {
		return "", 0
	}
	fi, err := os.Stat(filepath.Join(snapBlobDir, name+"_"+rev+".snap"))
	if err != nil {
		return "", 0
	}
	return fi.ModTime().UTC().Format(time.RFC3339), fi.Size()
}

// parseFlatpakPackages parses `flatpak list --columns=application,name,version,origin,arch`.
// flatpak separates columns with tabs when not writing to a terminal; names
// contain spaces, so tabs are preferred and whitespace splitting is only a
// fallback. flatpak keeps no install date. The origin (the remote, e.g.
// flathub) is reported as the publisher.
func parseFlatpakPackages(output []byte, packages *[]SoftwareInfo) {
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "application") {
			continue
		}
		parts := splitColumns(line, strings.Fields)
		if len(parts) < 3 {
			continue
		}
		name := parts[1]
		if name == "" {
			name = parts[0]
		}
		sw := SoftwareInfo{
			Name:             name,
			InstalledVersion: parts[2],
			SoftwarePackage:  parts[0],
			Source:           sourceFlatpakPackages,
			Type:             sourceFlatpakPackages,
		}
		if len(parts) > 3 {
			sw.Publisher = parts[3]
		}
		if len(parts) > 4 {
			sw.Architecture = normalizeArch(parts[4])
		}
		*packages = append(*packages, sw)
	}
}

// chromeExtDirGlobs returns Chrome extension directory glob patterns on Linux.
func chromeExtDirGlobs(home string) []string {
	return browserExtDirs(home,
		".config/google-chrome/Default/Extensions",
		".config/google-chrome/Profile */Extensions")
}

// edgeExtDirGlobs returns Edge extension directory glob patterns on Linux.
func edgeExtDirGlobs(home string) []string {
	return browserExtDirs(home,
		".config/microsoft-edge/Default/Extensions",
		".config/microsoft-edge/Profile */Extensions")
}

// braveExtDirGlobs returns Brave extension directory glob patterns on Linux.
func braveExtDirGlobs(home string) []string {
	return browserExtDirs(home,
		".config/BraveSoftware/Brave-Browser/Default/Extensions",
		".config/BraveSoftware/Brave-Browser/Profile */Extensions")
}

// firefoxProfileGlobs returns Firefox profile directory glob patterns on Linux.
func firefoxProfileGlobs(home string) []string {
	return browserExtDirs(home, ".mozilla/firefox/*")
}
