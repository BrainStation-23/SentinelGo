package models

import "encoding/json"

const (
	LogCategorySystem   = "SYSTEM_LOG"
	LogCategorySecurity = "SECURITY_LOG"
	LogCategoryAgent    = "AGENT_LOG"
	LogCategoryNetwork  = "NETWORK_LOG"
	LogCategoryStorage  = "STORAGE_LOG"
	LogCategoryUser     = "USER_LOG"
	LogCategoryPolicy   = "POLICY_LOG"
	LogCategoryRemote   = "REMOTE_ACTION_LOG"
	LogCategoryEPM      = "EPM_ELEVATION_LOG"
)

type AuditLog struct {
	Timestamp    string          `json:"created_at"`
	AgentID      string          `json:"agent_id"`
	DeviceID     string          `json:"device_id"`
	LogCategory  string          `json:"log_category"`
	EventType    string          `json:"event_type"`
	OSType       string          `json:"os_type"`
	AgentVersion string          `json:"agent_version"`
	Severity     string          `json:"severity"`
	Source       string          `json:"source"`
	EventData    json.RawMessage `json:"event_data"`
}
