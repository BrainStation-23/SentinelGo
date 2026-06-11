package software

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// getChromeExtensions returns installed Chrome extensions for the current user.
// Path discovery is delegated to the platform-specific chromeExtDirGlobs function.
func (s *SoftwareService) getChromeExtensions() []SoftwareInfo {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
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
	return extensions
}

// getFirefoxExtensions returns installed Firefox extensions for the current user.
// Path discovery is delegated to the platform-specific firefoxProfileGlobs function.
func (s *SoftwareService) getFirefoxExtensions() []SoftwareInfo {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
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
	return extensions
}

// getEdgeExtensions returns installed Edge extensions for the current user.
func (s *SoftwareService) getEdgeExtensions() []SoftwareInfo {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
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
	return extensions
}

// getBraveExtensions returns installed Brave extensions for the current user.
func (s *SoftwareService) getBraveExtensions() []SoftwareInfo {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
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
