package models

// ServiceInfo represents a single OS service (Windows Service, systemd unit, launchd daemon).
type ServiceInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`     // running, stopped, paused, failed, unknown
	StartType   string `json:"start_type"` // automatic, manual, disabled, static, system, unknown
	Description string `json:"description"`
	Source      string `json:"source"` // windows_services, systemd, launchd
	PID         int    `json:"pid"`    // 0 if not running
	RunAs       string `json:"run_as"` // service account (Windows: LocalSystem; Linux/macOS: empty)
	FirstSeenAt string `json:"first_seen_at"`
	UpdatedAt   string `json:"updated_at"`
}
