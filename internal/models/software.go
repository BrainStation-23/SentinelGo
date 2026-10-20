package models

// SoftwareInfo represents a currently installed software entry.
type SoftwareInfo struct {
	Name             string `json:"name"`
	Source           string `json:"source"`
	InstalledVersion string `json:"installed_version"`
	Type             string `json:"type"`
	DisplayName      string `json:"display_name"`
	SoftwarePackage  string `json:"software_package"`
	AppStoreApp      string `json:"app_store_app"`
	LastOpened       string `json:"last_opened"`
	FilePath         string `json:"file_path"`
	FirstSeenAt      string `json:"first_seen_at"`

	// Optional metadata. A collector leaves a field zero when the platform has
	// no such value or it could not be read; the upload then omits it.
	Publisher    string `json:"publisher,omitempty"`
	InstallDate  string `json:"install_date,omitempty"` // RFC 3339
	SizeBytes    int64  `json:"size_bytes,omitempty"`
	Architecture string `json:"architecture,omitempty"` // see normalizeArch
	BundleID     string `json:"bundle_id,omitempty"`    // macOS CFBundleIdentifier
}
