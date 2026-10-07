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
	name, version := parseExtensionManifest(data, fallbackID)

	// Resolve i18n message keys (e.g., __MSG_extName__)
	if strings.HasPrefix(name, "__MSG_") {
		name = resolveI18nName(path, name, fallbackID)
	}

	firstSeen := time.Now().UTC().Format(time.RFC3339)
	if fi, err := os.Stat(path); err == nil {
		firstSeen = fi.ModTime().UTC().Format(time.RFC3339)
	}
	return &SoftwareInfo{
		Name:             fallbackID,
		DisplayName:      name,
		InstalledVersion: version,
		Source:           source,
		Type:             extType,
		FilePath:         path,
		FirstSeenAt:      firstSeen,
	}
}

// parseExtensionManifest extracts the name and version from manifest.json
// bytes. It does no I/O, so it can be fuzzed: manifests are written by the
// extension itself and are untrusted. The name falls back to fallbackID when
// the manifest is malformed or has no name; it may still be an unresolved
// "__MSG_*__" i18n key, which the caller resolves against the locale files.
func parseExtensionManifest(data []byte, fallbackID string) (name, version string) {
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
	return m.Name, m.Version
}

// resolveI18nName attempts to resolve an i18n message key like "__MSG_extName__"
// by reading the extension's locale messages.json files. Returns the resolved
// name or the fallbackID if resolution fails.
func resolveI18nName(manifestPath, msgKey, fallbackID string) string {
	key := normalizeI18nKey(msgKey)
	if key == "" {
		return fallbackID
	}

	// Chrome extension locale files typically use lowercase keys.
	// Try both the original case and lowercase versions.
	keyVariants := []string{key, strings.ToLower(key)}

	localesDir, entries, ok := findExtensionLocalesDir(manifestPath)
	if !ok {
		return fallbackID
	}

	// Preferred locales to try first (in order).
	preferredLocales := []string{"en", "en_US", "en_GB", "en_CA"}
	if name, ok := tryLocaleVariants(localesDir, preferredLocales, keyVariants); ok {
		return name
	}

	// Then try any remaining available locale.
	otherLocales := otherLocaleNames(entries, preferredLocales)
	if name, ok := tryLocaleVariants(localesDir, otherLocales, keyVariants); ok {
		return name
	}

	return fallbackID
}

// normalizeI18nKey extracts key from the "__MSG_key__" format.
func normalizeI18nKey(msgKey string) string {
	key := strings.TrimPrefix(msgKey, "__MSG_")
	key = strings.TrimSuffix(key, "__")
	return key
}

// findExtensionLocalesDir locates the "_locales" directory for an extension.
// For Chrome extensions, _locales is in the version directory (same dir as
// manifest.json). For Firefox extensions, _locales is in the extension root.
func findExtensionLocalesDir(manifestPath string) (string, []os.DirEntry, bool) {
	manifestDir := filepath.Dir(manifestPath)

	// First try: _locales in the same directory as manifest.json (Chrome-style).
	localesDir := filepath.Join(manifestDir, "_locales")
	if entries, err := os.ReadDir(localesDir); err == nil {
		return localesDir, entries, true
	}

	// Second try: _locales in parent directory (Firefox-style or alternative Chrome structure).
	localesDir = filepath.Join(filepath.Dir(manifestDir), "_locales")
	entries, err := os.ReadDir(localesDir)
	if err != nil {
		return "", nil, false
	}
	return localesDir, entries, true
}

// tryLocaleVariants attempts to read a message for each locale/key-variant
// combination, returning the first non-empty result found.
func tryLocaleVariants(localesDir string, locales, keyVariants []string) (string, bool) {
	for _, locale := range locales {
		for _, keyVariant := range keyVariants {
			if name := readLocaleMessage(localesDir, locale, keyVariant); name != "" {
				return name, true
			}
		}
	}
	return "", false
}

// otherLocaleNames returns the directory-entry locale names from entries that
// are not already present in preferredLocales.
func otherLocaleNames(entries []os.DirEntry, preferredLocales []string) []string {
	var locales []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		locale := entry.Name()
		if isPreferredLocale(locale, preferredLocales) {
			continue
		}
		locales = append(locales, locale)
	}
	return locales
}

func isPreferredLocale(locale string, preferredLocales []string) bool {
	for _, pref := range preferredLocales {
		if locale == pref {
			return true
		}
	}
	return false
}

// readLocaleMessage reads a specific locale's messages.json and returns the
// value for the given key, or empty string if not found.
func readLocaleMessage(localesDir, locale, key string) string {
	messagesPath := filepath.Join(localesDir, locale, "messages.json")
	// #nosec G304 - locale is an os.ReadDir entry name (no separators) and only messages.json is read
	data, err := os.ReadFile(messagesPath)
	if err != nil {
		return ""
	}
	return parseLocaleMessage(data, key)
}

// parseLocaleMessage returns the "message" value for key from messages.json
// bytes, or "" if it is absent. Only the requested entry is decoded, so other
// entries with non-string fields (e.g. Chrome's "placeholders" objects) do not
// make the whole lookup fail. No I/O, so it can be fuzzed.
func parseLocaleMessage(data []byte, key string) string {
	var messages map[string]json.RawMessage
	if err := json.Unmarshal(data, &messages); err != nil {
		return ""
	}
	raw, ok := messages[key]
	if !ok {
		return ""
	}
	// Chrome Web Store extensions use the "message" field.
	var entry struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &entry); err != nil {
		return ""
	}
	return entry.Message
}
