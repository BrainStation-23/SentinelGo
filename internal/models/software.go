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
	// SHA256Hash is the hex-encoded SHA-256 digest of the primary installed
	// binary (identified via FilePath). Populated by the software enrichment
	// pass after collection; empty when FilePath is unknown or the file cannot
	// be read (e.g. permission-denied, SIP-protected path on macOS).
	SHA256Hash string `json:"sha256_hash,omitempty"`
	// Publisher is the vendor or signing authority for the software entry.
	// On Windows this comes from the registry Publisher field; on macOS it is
	// the system_profiler obtained_from value (e.g. "apple",
	// "identified_developer", "mac_app_store"). Empty for Linux package
	// managers and browser extensions where no publisher metadata is available.
	Publisher string `json:"publisher,omitempty"`
}
