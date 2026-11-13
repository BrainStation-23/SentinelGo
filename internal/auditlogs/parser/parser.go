package parser

import (
	"encoding/json"
	"runtime"
	"strings"
	"time"

	"sentinelgo/internal/auditlogs/collector"
	"sentinelgo/internal/models"
)

// ParserConfig provides agent-level fields to populate on each parsed log.
type ParserConfig struct {
	AgentID      string
	DeviceID     string
	OSType       string
	AgentVersion string
	// MaxEventDataBytes is the server's limit on one row's event_data (from
	// the enqueue response). 0 means DefaultMaxEventDataBytes.
	MaxEventDataBytes int
}

// Parser normalizes raw OS log entries into the AuditLog model.
type Parser interface {
	Parse(entries []collector.RawLogEntry, cfg ParserConfig) []models.AuditLog
}

// DefaultParser implements the Parser interface with standard
// severity and category mapping rules.
type DefaultParser struct{}

// NewParser creates a new DefaultParser.
func NewParser() *DefaultParser {
	return &DefaultParser{}
}

// Parse converts raw log entries into normalized AuditLog structs.
func (p *DefaultParser) Parse(entries []collector.RawLogEntry, cfg ParserConfig) []models.AuditLog {
	result := make([]models.AuditLog, 0, len(entries))

	osType := cfg.OSType
	if osType == "" {
		osType = runtime.GOOS
	}

	target := EventDataTarget(cfg.MaxEventDataBytes)

	for i := range entries {
		raw := &entries[i]

		// A zero timestamp means the collector couldn't parse the event's own
		// time: use the collection time and say so in event_data (#437).
		ts, collected := raw.Timestamp, raw.Timestamp.IsZero()
		if collected {
			ts = time.Now()
		}
		eventData := CapEventData(marshalEventData(raw, collected), target)

		log := models.AuditLog{
			Timestamp:    ts.UTC().Format(time.RFC3339),
			AgentID:      cfg.AgentID,
			DeviceID:     cfg.DeviceID,
			LogCategory:  mapCategory(raw.Source),
			EventType:    mapEventType(raw),
			OSType:       osType,
			AgentVersion: cfg.AgentVersion,
			Severity:     grade(raw),
			Source:       raw.Source,
			EventData:    eventData,
		}

		result = append(result, log)
	}

	return result
}

// normalizeSeverity maps OS-native severity values to a standard set.
func normalizeSeverity(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "emergency", "emerg", "0":
		return "critical"
	case "alert", "1":
		return "critical"
	case "critical", "crit", "2":
		return "critical"
	case "error", "err", "3":
		return "high"
	case "warning", "warn", "4":
		return "medium"
	case "notice", "5":
		return "low"
	case "info", "informational", "information", "6":
		return "info"
	case "debug", "7":
		return "info"
	default:
		return "info"
	}
}

// mapCategory maps a raw source name to a LogCategory constant.
func mapCategory(source string) string {
	s := strings.ToLower(source)

	switch {
	case strings.Contains(s, "security") || strings.Contains(s, "auth"):
		return models.LogCategorySecurity
	case strings.Contains(s, "system") || strings.Contains(s, "kern") || strings.Contains(s, "syslog"):
		return models.LogCategorySystem
	case strings.Contains(s, "network"):
		return models.LogCategoryNetwork
	case strings.Contains(s, "policy") || strings.Contains(s, "defender"):
		return models.LogCategoryPolicy
	case strings.Contains(s, "user") || strings.Contains(s, "login"):
		return models.LogCategoryUser
	case strings.Contains(s, "storage") || strings.Contains(s, "disk"):
		return models.LogCategoryStorage
	case strings.Contains(s, "remote") || strings.Contains(s, "mdm"):
		return models.LogCategoryRemote
	case strings.Contains(s, "agent"):
		return models.LogCategoryAgent
	case strings.Contains(s, "powershell") || strings.Contains(s, "application"):
		return models.LogCategorySystem
	case strings.Contains(s, "journal"):
		return models.LogCategorySystem
	case strings.Contains(s, "crash") || strings.Contains(s, "diagnostic"):
		return models.LogCategorySystem
	default:
		return models.LogCategorySystem
	}
}

// mapEventType derives an event type from the raw entry.
func mapEventType(raw *collector.RawLogEntry) string {
	// Use EventID directly if it maps to a known Windows event
	switch raw.EventID {
	case "4624":
		return "local_login_success"
	case "4625":
		return "local_login_failure"
	case "4672":
		return "privilege_escalation"
	case "4634":
		return "logoff"
	case "7036":
		return "service_state_change"
	case "1074":
		return "shutdown"
	case "6005":
		return "boot"
	case "6006":
		return "shutdown"
	}

	// Fall back to metadata or source-based inference
	if et, ok := raw.Metadata["event_type"]; ok && et != "" {
		return et
	}

	src := strings.ToLower(raw.Source)
	switch {
	case strings.Contains(src, "auth"):
		return "authentication_event"
	case strings.Contains(src, "kern"):
		return "kernel_event"
	case strings.Contains(src, "crash"):
		return "crash"
	default:
		return "system_event"
	}
}

// marshalEventData serializes the raw entry's message and metadata into a JSON
// string. collected marks a row whose timestamp is the collection time.
func marshalEventData(raw *collector.RawLogEntry, collected bool) json.RawMessage {
	data := make(map[string]interface{}, len(raw.Metadata)+3)

	if raw.RawMessage != "" {
		data["message"] = raw.RawMessage
	}
	if raw.EventID != "" {
		data["event_id"] = raw.EventID
	}

	for k, v := range raw.Metadata {
		data[k] = v
	}
	if collected {
		data["timestamp_source"] = "collected"
	}

	b, err := json.Marshal(data)
	if err != nil {
		return json.RawMessage(`{"error":"failed to marshal event data"}`)
	}
	return b
}
