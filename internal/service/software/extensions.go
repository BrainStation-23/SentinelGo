package software

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// manifestFile is the per-extension metadata file name shared by every browser.
const manifestFile = "manifest.json"

// appendExtensions runs every browser-extension collector, appending results to sw.
// Note: LastOpened is not collected for extensions on any platform.
func (s *SoftwareService) appendExtensions(sw *[]SoftwareInfo) {
	if items, ok := s.getChromeExtensions(); ok {
		*sw = append(*sw, items...)
	}
	if items, ok := s.getFirefoxExtensions(); ok {
		*sw = append(*sw, items...)
	}
	if items, ok := s.getEdgeExtensions(); ok {
		*sw = append(*sw, items...)
	}
	if items, ok := s.getBraveExtensions(); ok {
		*sw = append(*sw, items...)
	}
}

// getChromeExtensions returns installed Chrome extensions across all users.
func (s *SoftwareService) getChromeExtensions() ([]SoftwareInfo, bool) {
	var extensions []SoftwareInfo
	for _, home := range userHomeDirs() {
		extensions = append(extensions, scanChromiumExtensions(chromeExtDirGlobs(home), "chrome_extensions")...)
	}
	return extensions, true
}

// getFirefoxExtensions returns installed Firefox extensions across all users.
func (s *SoftwareService) getFirefoxExtensions() ([]SoftwareInfo, bool) {
	var extensions []SoftwareInfo
	for _, home := range userHomeDirs() {
		for _, pattern := range firefoxProfileGlobs(home) {
			profiles, _ := filepath.Glob(pattern)
			for _, profile := range profiles {
				extensions = append(extensions, scanFirefoxProfile(profile)...)
			}
		}
	}
	return extensions, true
}

// scanFirefoxProfile scans one Firefox profile's extensions directory, whose
// layout is <profile>/extensions/<extID>/manifest.json (flat, no version dir).
func scanFirefoxProfile(profile string) []SoftwareInfo {
	extBase := filepath.Join(profile, "extensions")
	entries, err := os.ReadDir(extBase)
	if err != nil {
		return nil
	}
	var extensions []SoftwareInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		extID := entry.Name()
		mPath := filepath.Join(extBase, extID, manifestFile)
		if info := readExtensionManifest(mPath, "firefox_extensions", "firefox_extensions", extID); info != nil {
			extensions = append(extensions, *info)
		}
	}
	return extensions
}

// getEdgeExtensions returns installed Edge extensions across all users.
func (s *SoftwareService) getEdgeExtensions() ([]SoftwareInfo, bool) {
	var extensions []SoftwareInfo
	for _, home := range userHomeDirs() {
		extensions = append(extensions, scanChromiumExtensions(edgeExtDirGlobs(home), "edge_extensions")...)
	}
	return extensions, true
}

// getBraveExtensions returns installed Brave extensions across all users.
func (s *SoftwareService) getBraveExtensions() ([]SoftwareInfo, bool) {
	var extensions []SoftwareInfo
	for _, home := range userHomeDirs() {
		extensions = append(extensions, scanChromiumExtensions(braveExtDirGlobs(home), "brave_extensions")...)
	}
	return extensions, true
}

// scanChromiumExtensions walks Chromium-family extension directories (Chrome,
// Edge, Brave share the layout: <ExtDir>/<extID>/<version>/manifest.json) and
// returns one SoftwareInfo per extension, tagged with source/type.
func scanChromiumExtensions(globs []string, source string) []SoftwareInfo {
	var extensions []SoftwareInfo
	for _, pattern := range globs {
		matches, _ := filepath.Glob(pattern)
		for _, extBase := range matches {
			extensions = append(extensions, scanChromiumExtBase(extBase, source)...)
		}
	}
	return extensions
}

// scanChromiumExtBase scans one Chromium "Extensions" directory, whose layout is
// <extBase>/<extID>/<version>/manifest.json.
func scanChromiumExtBase(extBase, source string) []SoftwareInfo {
	entries, err := os.ReadDir(extBase)
	if err != nil {
		return nil
	}
	var extensions []SoftwareInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		extID := entry.Name()
		manifests, _ := filepath.Glob(filepath.Join(extBase, extID, "*", manifestFile))
		for _, mPath := range manifests {
			if info := readExtensionManifest(mPath, source, source, extID); info != nil {
				extensions = append(extensions, *info)
				break
			}
		}
	}
	return extensions
}

// readExtensionManifest reads a browser extension's manifest.json and returns
// a SoftwareInfo populated from it. fallbackID is used as the name when the
// manifest name is absent or is an unresolved i18n message key.
func readExtensionManifest(path, source, extType, fallbackID string) *SoftwareInfo {
	// #nosec G304 - path is safely generated from filepath.Glob with controlled base directory
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		m.Name = fallbackID
	}
	if m.Name == "" {
		m.Name = fallbackID
	}

	// Resolve i18n message keys (e.g., __MSG_extName__)
	if strings.HasPrefix(m.Name, "__MSG_") {
		m.Name = resolveI18nName(path, m.Name, fallbackID)
	}

	firstSeen := time.Now().UTC().Format(time.RFC3339)
	if fi, err := os.Stat(path); err == nil {
		firstSeen = fi.ModTime().UTC().Format(time.RFC3339)
	}
	return &SoftwareInfo{
		Name:             fallbackID,
		DisplayName:      m.Name,
		InstalledVersion: m.Version,
		Source:           source,
		Type:             extType,
		FilePath:         path,
		FirstSeenAt:      firstSeen,
	}
}

// resolveI18nName attempts to resolve an i18n message key like "__MSG_extName__"
// by reading the extension's locale messages.json files. Returns the resolved
// name or the fallbackID if resolution fails.
func resolveI18nName(manifestPath, msgKey, fallbackID string) string {
	// Extract key from __MSG_key__ format
	key := strings.TrimPrefix(msgKey, "__MSG_")
	key = strings.TrimSuffix(key, "__")
	if key == "" {
		return fallbackID
	}

	// Chrome extension locale files typically use lowercase keys
	// Try both the original case and lowercase versions
	keyVariants := []string{key, strings.ToLower(key)}

	// For Chrome extensions, _locales is in the version directory (same dir as manifest.json)
	// For Firefox extensions, _locales is in the extension root
	manifestDir := filepath.Dir(manifestPath)

	// First try: _locales in the same directory as manifest.json (Chrome-style)
	localesDir := filepath.Join(manifestDir, "_locales")
	entries, err := os.ReadDir(localesDir)
	if err != nil {
		// Second try: _locales in parent directory (Firefox-style or alternative Chrome structure)
		localesDir = filepath.Join(filepath.Dir(manifestDir), "_locales")
		entries, err = os.ReadDir(localesDir)
		if err != nil {
			return fallbackID
		}
	}

	// Preferred locales to try (in order)
	preferredLocales := []string{"en", "en_US", "en_GB", "en_CA"}

	// First try preferred locales with all key variants
	for _, locale := range preferredLocales {
		for _, keyVariant := range keyVariants {
			if name := readLocaleMessage(localesDir, locale, keyVariant); name != "" {
				return name
			}
		}
	}

	// Then try any available locale with all key variants
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		locale := entry.Name()
		// Skip if already tried
		skip := false
		for _, pref := range preferredLocales {
			if locale == pref {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		for _, keyVariant := range keyVariants {
			if name := readLocaleMessage(localesDir, locale, keyVariant); name != "" {
				return name
			}
		}
	}

	return fallbackID
}

// readLocaleMessage reads a specific locale's messages.json and returns the
// value for the given key, or empty string if not found.
func readLocaleMessage(localesDir, locale, key string) string {
	messagesPath := filepath.Join(localesDir, locale, "messages.json")
	data, err := os.ReadFile(messagesPath)
	if err != nil {
		return ""
	}

	var messages map[string]map[string]string
	if err := json.Unmarshal(data, &messages); err != nil {
		return ""
	}

	// Chrome Web Store extensions use "message" field
	if msg, ok := messages[key]; ok {
		if name, ok := msg["message"]; ok {
			return name
		}
	}

	return ""
}
