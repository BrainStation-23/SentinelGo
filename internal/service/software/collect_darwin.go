package software

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"sentinelgo/internal/binpath"
)

const mdlsBatchSize = 200

// mdlsAttrs are the Spotlight attributes read for every application bundle, in
// the order mdls -raw prints them.
var mdlsAttrs = []string{
	"kMDItemLastUsedDate",
	"kMDItemDateAdded",
	"kMDItemPhysicalSize",
	"kMDItemCFBundleIdentifier",
}

// bundleMeta is the Spotlight metadata of one application bundle. Zero values
// mean the attribute was (null) or unparsable.
type bundleMeta struct {
	LastUsed  string // RFC 3339
	DateAdded string // RFC 3339
	Size      int64
	BundleID  string
}

// runCollectCmd runs an enumeration command under collectCmdTimeout so a hung tool
// (e.g. a stalled system_profiler) errors out instead of blocking the sync goroutine.
// The tool must be at one of its known paths (binpath.Lookup): PATH is never
// searched, so a brew installed outside Homebrew's standard prefixes is skipped
// rather than letting a substituted binary run with the agent's privileges.
// A variable so tests can stub the commands.
var runCollectCmd = func(name string, args ...string) ([]byte, error) {
	path, ok := binpath.Lookup(name)
	if !ok {
		return nil, fmt.Errorf("%s not found at a known path", name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), collectCmdTimeout)
	defer cancel()
	// #nosec G204 - binpath.Lookup returns a fixed, verified absolute path; not attacker input
	return exec.CommandContext(ctx, path, args...).Output()
}

// batchMdlsMetadata queries Spotlight metadata for a set of app paths. Returns
// a map of path → metadata; paths whose batch failed are omitted.
func batchMdlsMetadata(paths []string) map[string]bundleMeta {
	result := make(map[string]bundleMeta, len(paths))
	for i := 0; i < len(paths); i += mdlsBatchSize {
		end := i + mdlsBatchSize
		if end > len(paths) {
			end = len(paths)
		}
		batch := paths[i:end]
		args := []string{"-raw"}
		for _, a := range mdlsAttrs {
			args = append(args, "-name", a)
		}
		args = append(args, batch...)
		out, err := runCollectCmd("mdls", args...)
		if err != nil {
			log.Printf("software: mdls batch failed: %v", err)
			continue
		}
		if !parseMdlsRaw(out, batch, result) {
			log.Printf("software: mdls batch returned an unexpected number of values; skipped")
		}
	}
	return result
}

// parseMdlsRaw parses `mdls -raw -name A -name B … path1 path2 …` output: one
// value per (path, attribute), path-major, "(null)" for a missing attribute.
// mdls(1) documents -raw values as NUL-separated; output without any NUL is
// split on newlines instead, which is safe because none of mdlsAttrs is
// multi-line. It returns false, adding nothing, when the value count does not
// match, since the values could then not be attributed to paths.
func parseMdlsRaw(output []byte, paths []string, result map[string]bundleMeta) bool {
	sep := "\x00"
	if !strings.Contains(string(output), sep) {
		sep = "\n"
	}
	values := strings.Split(string(output), sep)
	want := len(paths) * len(mdlsAttrs)
	if len(values) == want+1 && strings.TrimSpace(values[want]) == "" {
		values = values[:want]
	}
	if want == 0 || len(values) != want {
		return false
	}
	for i, p := range paths {
		v := values[i*len(mdlsAttrs) : (i+1)*len(mdlsAttrs)]
		var m bundleMeta
		m.LastUsed = parseMdlsDate(v[0])
		m.DateAdded = parseMdlsDate(v[1])
		if n, err := strconv.ParseInt(strings.TrimSpace(v[2]), 10, 64); err == nil && n > 0 {
			m.Size = n
		}
		if id := strings.TrimSpace(v[3]); id != "(null)" {
			m.BundleID = id
		}
		result[p] = m
	}
	return true
}

// parseMdlsDate parses an mdls date such as "2025-06-10 08:42:11 +0000" into
// RFC 3339, or "" for "(null)" and unparsable values.
func parseMdlsDate(val string) string {
	t, err := time.Parse("2006-01-02 15:04:05 -0700", strings.TrimSpace(val))
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
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
	cask, _ := s.getHomebrewCaskPackages()
	if len(brew)+len(cask) > 0 {
		formulae, casks := getHomebrewInfo()
		applyHomebrewInfo(brew, formulae)
		applyHomebrewInfo(cask, casks)
	}
	sw = append(sw, brew...)
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

	// Collect paths to batch-query Spotlight metadata.
	paths := make([]string, 0, len(applications))
	for _, app := range applications {
		if app.FilePath != "" {
			paths = append(paths, app.FilePath)
		}
	}
	if len(paths) > 0 {
		applyBundleMeta(applications, batchMdlsMetadata(paths))
	}
	fillBundleIDsFromInfoPlist(applications, runCollectCmd)

	return applications, true
}

// fillBundleIDsFromInfoPlist reads CFBundleIdentifier from Contents/Info.plist
// for every app that Spotlight gave no bundle ID: indexing is off for its
// volume (mdls prints "(null)"), or its mdls batch failed. run is
// runCollectCmd outside tests. An app whose plist can't be read keeps an
// empty BundleID; the scan doesn't fail.
func fillBundleIDsFromInfoPlist(applications []SoftwareInfo, run func(name string, args ...string) ([]byte, error)) {
	for i := range applications {
		app := &applications[i]
		if app.FilePath == "" || app.BundleID != "" {
			continue
		}
		plist := app.FilePath + "/Contents/Info.plist"
		out, err := run("plutil", "-extract", "CFBundleIdentifier", "raw", "-o", "-", plist)
		if err != nil {
			continue
		}
		app.BundleID = strings.TrimSpace(string(out))
	}
}

// applyBundleMeta copies Spotlight metadata onto the applications it belongs to.
func applyBundleMeta(applications []SoftwareInfo, meta map[string]bundleMeta) {
	for i := range applications {
		m, ok := meta[applications[i].FilePath]
		if !ok {
			continue
		}
		applications[i].LastOpened = m.LastUsed
		applications[i].InstallDate = m.DateAdded
		applications[i].SizeBytes = m.Size
		applications[i].BundleID = m.BundleID
	}
}

func (s *SoftwareService) getHomebrewPackages() ([]SoftwareInfo, bool) {
	output, err := runCollectCmd("brew", "list", "--versions")
	if err != nil {
		log.Printf("software: brew list --versions failed: %v", err)
		return nil, false
	}
	var packages []SoftwareInfo
	parseHomebrewPackages(output, &packages, sourceHomebrew)
	return packages, true
}

func (s *SoftwareService) getHomebrewCaskPackages() ([]SoftwareInfo, bool) {
	output, err := runCollectCmd("brew", "list", "--cask", "--versions")
	if err != nil {
		log.Printf("software: brew list --cask --versions failed: %v", err)
		return nil, false
	}
	var packages []SoftwareInfo
	parseHomebrewPackages(output, &packages, sourceHomebrewCask)
	return packages, true
}

// brewMeta is the install metadata brew keeps for one formula or cask.
type brewMeta struct {
	Tap         string
	InstallDate string // RFC 3339
}

// getHomebrewInfo returns install metadata for every installed formula and
// cask, keyed by name / token. Best-effort: on failure both maps are nil and
// the packages are reported without it.
func getHomebrewInfo() (formulae, casks map[string]brewMeta) {
	output, err := runCollectCmd("brew", "info", "--json=v2", "--installed")
	if err != nil {
		log.Printf("software: brew info --json=v2 --installed failed: %v", err)
		return nil, nil
	}
	return parseHomebrewInfo(output)
}

// parseHomebrewInfo parses `brew info --json=v2 --installed`. A formula's
// install time is on its installed keg; a cask's is installed_time. Both are
// Unix seconds.
func parseHomebrewInfo(output []byte) (formulae, casks map[string]brewMeta) {
	var info struct {
		Formulae []struct {
			Name      string `json:"name"`
			Tap       string `json:"tap"`
			Installed []struct {
				Time int64 `json:"time"`
			} `json:"installed"`
		} `json:"formulae"`
		Casks []struct {
			Token         string `json:"token"`
			Tap           string `json:"tap"`
			InstalledTime int64  `json:"installed_time"`
		} `json:"casks"`
	}
	if err := json.Unmarshal(output, &info); err != nil {
		return nil, nil
	}
	formulae = make(map[string]brewMeta, len(info.Formulae))
	for _, f := range info.Formulae {
		m := brewMeta{Tap: f.Tap}
		// The last keg is the most recently installed version.
		if n := len(f.Installed); n > 0 {
			m.InstallDate = unixToRFC3339(f.Installed[n-1].Time)
		}
		formulae[f.Name] = m
	}
	casks = make(map[string]brewMeta, len(info.Casks))
	for _, c := range info.Casks {
		casks[c.Token] = brewMeta{Tap: c.Tap, InstallDate: unixToRFC3339(c.InstalledTime)}
	}
	return formulae, casks
}

// applyHomebrewInfo copies brew metadata onto packages. The tap (e.g.
// homebrew/core) is reported as the publisher, as flatpak's origin is on Linux.
func applyHomebrewInfo(packages []SoftwareInfo, meta map[string]brewMeta) {
	for i := range packages {
		m, ok := meta[packages[i].Name]
		if !ok {
			continue
		}
		packages[i].Publisher = m.Tap
		packages[i].InstallDate = m.InstallDate
	}
}

func unixToRFC3339(sec int64) string {
	if sec <= 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

type systemProfilerOutput struct {
	SPApplicationsDataType []struct {
		Name         string   `json:"_name"`
		Version      string   `json:"version"`
		Path         string   `json:"path"`
		ObtainedFrom string   `json:"obtained_from"`
		LastModified string   `json:"lastModified"`
		ArchKind     string   `json:"arch_kind"`
		SignedBy     []string `json:"signed_by"`
	} `json:"SPApplicationsDataType"`
}

// macPublisher derives an app's publisher from its code-signing chain. Apple's
// own apps are signed "Software Signing"; Developer ID apps carry the developer
// name in their leaf certificate, "Developer ID Application: Name (TEAMID)".
// Mac App Store apps are re-signed by Apple, so their developer is not
// available here and the publisher is left out.
func macPublisher(obtainedFrom string, signedBy []string) string {
	if obtainedFrom == "apple" {
		return "Apple Inc."
	}
	if len(signedBy) == 0 {
		return ""
	}
	leaf := strings.TrimSpace(signedBy[0])
	if leaf == "Software Signing" {
		return "Apple Inc."
	}
	name, ok := strings.CutPrefix(leaf, "Developer ID Application:")
	if !ok {
		return ""
	}
	name = strings.TrimSpace(name)
	if i := strings.LastIndex(name, " ("); i > 0 && strings.HasSuffix(name, ")") {
		name = name[:i]
	}
	return strings.TrimSpace(name)
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
		source := sourceApplications
		appStoreApp := ""
		if app.ObtainedFrom == "mac_app_store" {
			source = sourceAppStore
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
			Publisher:        macPublisher(app.ObtainedFrom, app.SignedBy),
			Architecture:     normalizeArch(app.ArchKind),
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
	return browserExtDirs(home,
		"Library/Application Support/Google/Chrome/Default/Extensions",
		"Library/Application Support/Google/Chrome/Profile */Extensions")
}

// edgeExtDirGlobs returns Edge extension directory glob patterns on macOS.
func edgeExtDirGlobs(home string) []string {
	return browserExtDirs(home,
		"Library/Application Support/Microsoft Edge/Default/Extensions",
		"Library/Application Support/Microsoft Edge/Profile */Extensions")
}

// braveExtDirGlobs returns Brave extension directory glob patterns on macOS.
func braveExtDirGlobs(home string) []string {
	return browserExtDirs(home,
		"Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions",
		"Library/Application Support/BraveSoftware/Brave-Browser/Profile */Extensions")
}

// firefoxProfileGlobs returns Firefox profile directory glob patterns on macOS.
func firefoxProfileGlobs(home string) []string {
	return browserExtDirs(home, "Library/Application Support/Firefox/Profiles/*")
}
