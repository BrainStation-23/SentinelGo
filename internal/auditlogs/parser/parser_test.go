package parser

import (
	"testing"
	"time"

	"sentinelgo/internal/auditlogs/collector"
	"sentinelgo/internal/models"
)

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"emergency", "critical"},
		{"emerg", "critical"},
		{"0", "critical"},
		{"alert", "critical"},
		{"1", "critical"},
		{"critical", "critical"},
		{"crit", "critical"},
		{"2", "critical"},
		{"error", "high"},
		{"err", "high"},
		{"3", "high"},
		{"warning", "medium"},
		{"warn", "medium"},
		{"4", "medium"},
		{"notice", "low"},
		{"5", "low"},
		{"info", "info"},
		{"informational", "info"},
		{"information", "info"},
		{"6", "info"},
		{"debug", "info"},
		{"7", "info"},
		{"", "info"},
		{"random_unknown", "info"},
		{"  ERROR  ", "high"},
		{"WARNING", "medium"},
		{"CRIT", "critical"},
	}
	for _, tt := range tests {
		got := normalizeSeverity(tt.input)
		if got != tt.want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestMapCategory(t *testing.T) {
	tests := []struct {
		source string
		want   string
	}{
		{"security", models.LogCategorySecurity},
		{"auth", models.LogCategorySecurity},
		{"windows_security", models.LogCategorySecurity},
		{"authd", models.LogCategorySecurity},
		{"SECURITY", models.LogCategorySecurity},
		{"AUTH", models.LogCategorySecurity},
		{"system", models.LogCategorySystem},
		{"kern", models.LogCategorySystem},
		{"kernel", models.LogCategorySystem},
		{"syslog", models.LogCategorySystem},
		{"network", models.LogCategoryNetwork},
		{"network_monitor", models.LogCategoryNetwork},
		{"policy", models.LogCategoryPolicy},
		{"defender", models.LogCategoryPolicy},
		{"windows_defender", models.LogCategoryPolicy},
		{"user", models.LogCategoryUser},
		{"login", models.LogCategoryUser},
		{"storage", models.LogCategoryStorage},
		{"disk", models.LogCategoryStorage},
		{"remote", models.LogCategoryRemote},
		{"mdm", models.LogCategoryRemote},
		{"agent", models.LogCategoryAgent},
		{"sentinelgo_agent", models.LogCategoryAgent},
		{"powershell", models.LogCategorySystem},
		{"application", models.LogCategorySystem},
		{"journal", models.LogCategorySystem},
		{"crash", models.LogCategorySystem},
		{"diagnostic", models.LogCategorySystem},
		{"", models.LogCategorySystem},
		{"totally_unknown_source", models.LogCategorySystem},
	}
	for _, tt := range tests {
		got := mapCategory(tt.source)
		if got != tt.want {
			t.Errorf("mapCategory(%q) = %q, want %q", tt.source, got, tt.want)
		}
	}
}

func TestMapEventType(t *testing.T) {
	tests := []struct {
		name  string
		entry collector.RawLogEntry
		want  string
	}{
		{
			name:  "windows event 4624 login success",
			entry: collector.RawLogEntry{EventID: "4624"},
			want:  "local_login_success",
		},
		{
			name:  "windows event 4625 login failure",
			entry: collector.RawLogEntry{EventID: "4625"},
			want:  "local_login_failure",
		},
		{
			name:  "windows event 4672 privilege escalation",
			entry: collector.RawLogEntry{EventID: "4672"},
			want:  "privilege_escalation",
		},
		{
			name:  "windows event 4634 logoff",
			entry: collector.RawLogEntry{EventID: "4634"},
			want:  "logoff",
		},
		{
			name:  "windows event 7036 service state change",
			entry: collector.RawLogEntry{EventID: "7036"},
			want:  "service_state_change",
		},
		{
			name:  "windows event 1074 shutdown",
			entry: collector.RawLogEntry{EventID: "1074"},
			want:  "shutdown",
		},
		{
			name:  "windows event 6005 boot",
			entry: collector.RawLogEntry{EventID: "6005"},
			want:  "boot",
		},
		{
			name:  "windows event 6006 shutdown",
			entry: collector.RawLogEntry{EventID: "6006"},
			want:  "shutdown",
		},
		{
			name:  "metadata event_type takes priority",
			entry: collector.RawLogEntry{Metadata: map[string]string{"event_type": "custom_event"}},
			want:  "custom_event",
		},
		{
			name:  "empty metadata event_type falls through to source inference",
			entry: collector.RawLogEntry{Source: "auth", Metadata: map[string]string{"event_type": ""}},
			want:  "authentication_event",
		},
		{
			name:  "auth source inference",
			entry: collector.RawLogEntry{Source: "auth.log"},
			want:  "authentication_event",
		},
		{
			name:  "kern source inference",
			entry: collector.RawLogEntry{Source: "kern.log"},
			want:  "kernel_event",
		},
		{
			name:  "crash source inference",
			entry: collector.RawLogEntry{Source: "crash_reporter"},
			want:  "crash",
		},
		{
			name:  "unknown source defaults to system_event",
			entry: collector.RawLogEntry{Source: "something_else"},
			want:  "system_event",
		},
		{
			name:  "empty entry defaults to system_event",
			entry: collector.RawLogEntry{},
			want:  "system_event",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapEventType(&tt.entry)
			if got != tt.want {
				t.Errorf("mapEventType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParse_EndToEnd(t *testing.T) {
	entries := []collector.RawLogEntry{
		{
			Timestamp:  time.Now(),
			Source:     "windows_security",
			EventID:    "4624",
			RawMessage: "User logged on",
			Severity:   "info",
			Metadata:   map[string]string{"user": "alice"},
		},
		{
			Timestamp:  time.Now(),
			Source:     "kern",
			RawMessage: "kernel panic",
			Severity:   "error",
		},
	}

	cfg := ParserConfig{
		AgentID:      "agent-1",
		DeviceID:     "device-1",
		OSType:       "windows",
		AgentVersion: "v1.0.0",
	}

	p := NewParser()
	logs := p.Parse(entries, cfg)

	if len(logs) != 2 {
		t.Fatalf("Parse() returned %d logs, want 2", len(logs))
	}

	if logs[0].AgentID != "agent-1" {
		t.Errorf("logs[0].AgentID = %q, want %q", logs[0].AgentID, "agent-1")
	}
	if logs[0].DeviceID != "device-1" {
		t.Errorf("logs[0].DeviceID = %q, want %q", logs[0].DeviceID, "device-1")
	}
	if logs[0].EventType != "local_login_success" {
		t.Errorf("logs[0].EventType = %q, want %q", logs[0].EventType, "local_login_success")
	}
	if logs[0].LogCategory != models.LogCategorySecurity {
		t.Errorf("logs[0].LogCategory = %q, want %q", logs[0].LogCategory, models.LogCategorySecurity)
	}
	if logs[0].Severity != "info" {
		t.Errorf("logs[0].Severity = %q, want %q", logs[0].Severity, "info")
	}
	if logs[0].OSType != "windows" {
		t.Errorf("logs[0].OSType = %q, want %q", logs[0].OSType, "windows")
	}
	if len(logs[0].EventData) == 0 {
		t.Error("logs[0].EventData should not be empty")
	}

	if logs[1].Severity != "high" {
		t.Errorf("logs[1].Severity = %q, want %q", logs[1].Severity, "high")
	}
	if logs[1].EventType != "kernel_event" {
		t.Errorf("logs[1].EventType = %q, want %q", logs[1].EventType, "kernel_event")
	}
}

func TestParse_Empty(t *testing.T) {
	p := NewParser()
	logs := p.Parse(nil, ParserConfig{})
	if len(logs) != 0 {
		t.Errorf("Parse(nil) returned %d logs, want 0", len(logs))
	}
}

func TestParse_OSTypeFallback(t *testing.T) {
	entries := []collector.RawLogEntry{
		{Timestamp: time.Now(), Source: "auth", Severity: "info"},
	}
	p := NewParser()
	logs := p.Parse(entries, ParserConfig{})
	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}
	if logs[0].OSType == "" {
		t.Error("OSType should not be empty when omitted from config (should fall back to runtime.GOOS)")
	}
}

func TestParse_EventDataContainsMessage(t *testing.T) {
	entries := []collector.RawLogEntry{
		{
			Timestamp:  time.Now(),
			Source:     "system",
			RawMessage: "disk full warning",
			Severity:   "warning",
		},
	}
	p := NewParser()
	logs := p.Parse(entries, ParserConfig{AgentID: "a", DeviceID: "d"})
	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}
	eventData := string(logs[0].EventData)
	if eventData == "" || eventData == "null" {
		t.Errorf("EventData = %q, want non-empty JSON", eventData)
	}
}
