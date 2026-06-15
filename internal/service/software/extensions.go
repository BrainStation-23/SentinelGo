package software

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// appendExtensions runs every browser-extension collector, appending each one's
// results to sw and recording each successfully-scanned source in scanned. A
// collector reports failure (and is left out of scanned) only when the scan
// could not run at all; an empty-but-successful scan is a legitimate "no
// extensions" state and still reconciles. Note: LastOpened is not collected for
// extensions on any platform (see readExtensionManifest) — tracked as a gap.
func (s *SoftwareService) appendExtensions(sw *[]SoftwareInfo, scanned map[string]bool) {
	if items, ok := s.getChromeExtensions(); ok {
		*sw = append(*sw, items...)
		scanned["chrome_extensions"] = true
	}
	if items, ok := s.getFirefoxExtensions(); ok {
		*sw = append(*sw, items...)
		scanned["firefox_extensions"] = true
	}
	if items, ok := s.getEdgeExtensions(); ok {
		*sw = append(*sw, items...)
		scanned["edge_extensions"] = true
	}
	if items, ok := s.getBraveExtensions(); ok {
		*sw = append(*sw, items...)
		scanned["brave_extensions"] = true
	}
}

// getChromeExtensions returns installed Chrome extensions for the current user.
// Path discovery is delegated to the platform-specific chromeExtDirGlobs function.
// The bool is false only when the user's home directory cannot be resolved (the
// scan could not run); an empty result with true means no extensions were found.
func (s *SoftwareService) getChromeExtensions() ([]SoftwareInfo, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, false
	}

	var extensions []SoftwareInfo
	for _, pattern := range chromeExtDirGlobs(home) {
		matches, _ := filepath.Glob(pattern)
		for _, extBase := range matches {
			entries, err := os.ReadDir(extBase)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				extID := entry.Name()
				manifests, _ := filepath.Glob(filepath.Join(extBase, extID, "*", "manifest.json"))
				for _, mPath := range manifests {
					if info := readExtensionManifest(mPath, "chrome_extensions", "chrome_extensions", extID); info != nil {
						extensions = append(extensions, *info)
						break
					}
				}
			}
		}
	}
	return extensions, true
}

// getFirefoxExtensions returns installed Firefox extensions for the current user.
// Path discovery is delegated to the platform-specific firefoxProfileGlobs function.
func (s *SoftwareService) getFirefoxExtensions() ([]SoftwareInfo, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, false
	}

	var extensions []SoftwareInfo
	for _, pattern := range firefoxProfileGlobs(home) {
		profiles, _ := filepath.Glob(pattern)
		for _, profile := range profiles {
			extBase := filepath.Join(profile, "extensions")
			entries, err := os.ReadDir(extBase)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				extID := entry.Name()
				mPath := filepath.Join(extBase, extID, "manifest.json")
				if info := readExtensionManifest(mPath, "firefox_extensions", "firefox_extensions", extID); info != nil {
					extensions = append(extensions, *info)
				}
			}
		}
	}
	return extensions, true
}

// getEdgeExtensions returns installed Edge extensions for the current user.
func (s *SoftwareService) getEdgeExtensions() ([]SoftwareInfo, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, false
	}

	var extensions []SoftwareInfo
	for _, pattern := range edgeExtDirGlobs(home) {
		matches, _ := filepath.Glob(pattern)
		for _, extBase := range matches {
			entries, err := os.ReadDir(extBase)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				extID := entry.Name()
				manifests, _ := filepath.Glob(filepath.Join(extBase, extID, "*", "manifest.json"))
				for _, mPath := range manifests {
					if info := readExtensionManifest(mPath, "edge_extensions", "edge_extensions", extID); info != nil {
						extensions = append(extensions, *info)
						break
					}
				}
			}
		}
	}
	return extensions, true
}

// getBraveExtensions returns installed Brave extensions for the current user.
func (s *SoftwareService) getBraveExtensions() ([]SoftwareInfo, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, false
	}

	var extensions []SoftwareInfo
	for _, pattern := range braveExtDirGlobs(home) {
		matches, _ := filepath.Glob(pattern)
		for _, extBase := range matches {
			entries, err := os.ReadDir(extBase)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				extID := entry.Name()
				manifests, _ := filepath.Glob(filepath.Join(extBase, extID, "*", "manifest.json"))
				for _, mPath := range manifests {
					if info := readExtensionManifest(mPath, "brave_extensions", "brave_extensions", extID); info != nil {
						extensions = append(extensions, *info)
						break
					}
				}
			}
		}
	}
	return extensions, true
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
	if m.Name == "" || strings.HasPrefix(m.Name, "__MSG_") {
		m.Name = fallbackID
	}

	now := time.Now().Format(time.RFC3339)
	firstSeen := now
	if fi, err := os.Stat(path); err == nil {
		firstSeen = fi.ModTime().UTC().Format(time.RFC3339)
	}
	return &SoftwareInfo{
		Name:             m.Name,
		DisplayName:      m.Name,
		InstalledVersion: m.Version,
		Source:           source,
		Type:             extType,
		FilePath:         path,
		Status:           "installed",
		FirstSeenAt:      firstSeen,
		LastSeenAt:       now,
		IsActive:         true,
	}
}
