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

	// Windows identifiers the console matches against upstream catalogs
	// (winget, Microsoft Store). Optional like the metadata above.
	ProductCode       string `json:"product_code,omitempty"`        // ARP key name; a {GUID} for MSI installs
	SystemComponent   bool   `json:"system_component,omitempty"`    // hidden from Apps & features
	ParentKeyName     string `json:"parent_key_name,omitempty"`     // set on child components and updates
	ReleaseType       string `json:"release_type,omitempty"`        // "Security Update", "Update", "Hotfix", …
	HomepageURL       string `json:"homepage_url,omitempty"`        // http(s) only, at most 500 chars
	PackageFamilyName string `json:"package_family_name,omitempty"` // Store apps
}
