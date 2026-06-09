package models

// SoftwareInfo represents an installed (or previously installed) software entry.
type SoftwareInfo struct {
	ID               int64  `json:"id"`
	Name             string `json:"name"`
	Source           string `json:"source"`
	InstalledVersion string `json:"installed_version"`
	Type             string `json:"type"`
	DisplayName      string `json:"display_name"`
	SoftwarePackage  string `json:"software_package"`
	AppStoreApp      string `json:"app_store_app"`
	LastOpened       string `json:"last_opened"`
	FilePath         string `json:"file_path"`
	Status           string `json:"status"`
	FirstSeenAt      string `json:"first_seen_at"`
	LastSeenAt       string `json:"last_seen_at"`
	IsActive         bool   `json:"is_active"`
}
