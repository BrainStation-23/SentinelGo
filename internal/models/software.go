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
}
