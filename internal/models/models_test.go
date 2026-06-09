package models_test

import (
	"encoding/json"
	"testing"

	"sentinelgo/internal/models"
)

func TestLogCategoryConstants(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"LogCategorySystem", models.LogCategorySystem},
		{"LogCategorySecurity", models.LogCategorySecurity},
		{"LogCategoryAgent", models.LogCategoryAgent},
		{"LogCategoryNetwork", models.LogCategoryNetwork},
		{"LogCategoryStorage", models.LogCategoryStorage},
		{"LogCategoryUser", models.LogCategoryUser},
		{"LogCategoryPolicy", models.LogCategoryPolicy},
		{"LogCategoryRemote", models.LogCategoryRemote},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.value == "" {
				t.Errorf("LogCategory %s should not be empty", tc.name)
			}
		})
	}
}

func TestAuditLog(t *testing.T) {
	log := models.AuditLog{
		Timestamp:    "2024-01-01T00:00:00Z",
		AgentID:      "test-agent-id",
		DeviceID:     "test-device-id",
		LogCategory:  models.LogCategorySystem,
		EventType:    "boot",
		OSType:       "linux",
		AgentVersion: "v1.0.0",
		Severity:     "info",
		Source:       "systemd",
		EventData:    json.RawMessage(`{"test": "data"}`),
	}

	if log.Timestamp == "" {
		t.Error("AuditLog Timestamp should not be empty")
	}
	if log.AgentID == "" {
		t.Error("AuditLog AgentID should not be empty")
	}
	if log.DeviceID == "" {
		t.Error("AuditLog DeviceID should not be empty")
	}
	if log.LogCategory == "" {
		t.Error("AuditLog LogCategory should not be empty")
	}
	if log.EventType == "" {
		t.Error("AuditLog EventType should not be empty")
	}
	if log.OSType == "" {
		t.Error("AuditLog OSType should not be empty")
	}
	if log.AgentVersion == "" {
		t.Error("AuditLog AgentVersion should not be empty")
	}
	if log.Severity == "" {
		t.Error("AuditLog Severity should not be empty")
	}
	if log.Source == "" {
		t.Error("AuditLog Source should not be empty")
	}
	if log.EventData == nil {
		t.Error("AuditLog EventData should not be nil")
	}
}
