package software

import "strings"

// Source values a collector can emit. The server (sentinel-ops) validates the
// source of every uploaded item against its own list, so adding or renaming a
// value here is a contract change: update allSources and the server together.
const (
	sourcePrograms        = "programs"
	sourceMicrosoftStore  = "microsoft_store"
	sourceApplications    = "applications"
	sourceAppStore        = "app_store"
	sourceHomebrew        = "homebrew"
	sourceHomebrewCask    = "homebrew_cask"
	sourceDebPackages     = "deb_packages"
	sourceRPMPackages     = "rpm_packages"
	sourceSnapPackages    = "snap_packages"
	sourceFlatpakPackages = "flatpak_packages"
	sourceChromeExt       = "chrome_extensions"
	sourceFirefoxExt      = "firefox_extensions"
	sourceEdgeExt         = "edge_extensions"
	sourceBraveExt        = "brave_extensions"
)

// allSources lists every source value above. contract_test.go pins it.
var allSources = []string{
	sourcePrograms, sourceMicrosoftStore,
	sourceApplications, sourceAppStore, sourceHomebrew, sourceHomebrewCask,
	sourceDebPackages, sourceRPMPackages, sourceSnapPackages, sourceFlatpakPackages,
	sourceChromeExt, sourceFirefoxExt, sourceEdgeExt, sourceBraveExt,
}

// normalizeArch maps the architecture names used by the different package
// managers onto one vocabulary: x64, x86, arm64, arm, universal (macOS fat
// binaries) and noarch (architecture-independent packages). Unknown values are
// passed through lower-cased; empty and placeholder values return "".
func normalizeArch(arch string) string {
	a := strings.ToLower(strings.TrimSpace(arch))
	switch a {
	case "", "(none)", "-", "unknown", "arch_other":
		return ""
	case "x64", "amd64", "x86_64", "x86-64", "arch_i64":
		return "x64"
	case "x86", "i386", "i486", "i586", "i686", "386", "arch_i32":
		return "x86"
	case "arm64", "aarch64", "arch_arm", "arch_ios":
		return "arm64"
	case "arm", "armhf", "armel", "armv7l", "armv7hl":
		return "arm"
	case "arch_arm_i64", "universal":
		return "universal"
	case "neutral", "all", "noarch":
		return "noarch"
	}
	return a
}

// stripEmail turns a "Name <address>" publisher or maintainer field into "Name".
func stripEmail(s string) string {
	if i := strings.Index(s, "<"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
