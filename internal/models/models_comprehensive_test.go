package models_test

import (
	"encoding/json"
	"testing"

	"sentinelgo/internal/models"
)

const testAgentID = "test-agent-id"
const testDeviceID = "test-device-id"

func TestAuditLog_JSONMarshaling(t *testing.T) {
	log := models.AuditLog{
		Timestamp:    "2024-01-01T00:00:00Z",
		AgentID:      testAgentID,
		DeviceID:     testDeviceID,
		LogCategory:  models.LogCategorySystem,
		EventType:    "boot",
		OSType:       "linux",
		AgentVersion: "v1.0.0",
		Severity:     "info",
		Source:       "systemd",
		EventData:    json.RawMessage(`{"test": "data"}`),
	}

	data, err := json.Marshal(log)
	if err != nil {
		t.Errorf("Marshal() failed: %v", err)
	}

	var unmarshaled models.AuditLog
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Errorf("Unmarshal() failed: %v", err)
	}

	if unmarshaled.Timestamp != log.Timestamp {
		t.Errorf("Timestamp mismatch: got %s, want %s", unmarshaled.Timestamp, log.Timestamp)
	}
}

func TestAuditLog_EmptyFields(t *testing.T) {
	log := models.AuditLog{}

	data, err := json.Marshal(log)
	if err != nil {
		t.Errorf("Marshal() should handle empty fields: %v", err)
	}

	var unmarshaled models.AuditLog
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Errorf("Unmarshal() should handle empty fields: %v", err)
	}
}

func TestAuditLog_EventData_Nil(t *testing.T) {
	log := models.AuditLog{
		Timestamp:    "2024-01-01T00:00:00Z",
		AgentID:      testAgentID,
		DeviceID:     testDeviceID,
		LogCategory:  models.LogCategorySystem,
		EventType:    "boot",
		OSType:       "linux",
		AgentVersion: "v1.0.0",
		Severity:     "info",
		Source:       "systemd",
		EventData:    nil,
	}

	data, err := json.Marshal(log)
	if err != nil {
		t.Errorf("Marshal() should handle nil EventData: %v", err)
	}

	var unmarshaled models.AuditLog
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Errorf("Unmarshal() should handle nil EventData: %v", err)
	}
}

func TestAuditLog_EventData_Empty(t *testing.T) {
	log := &models.AuditLog{
		AgentID:     testAgentID,
		DeviceID:    testDeviceID,
		EventType:   "test_event",
		LogCategory: models.LogCategorySystem,
		Severity:    "low",
		Source:      "systemd",
		EventData:   json.RawMessage(`{}`),
	}

	data, err := json.Marshal(log)
	if err != nil {
		t.Errorf("Marshal() should handle empty EventData: %v", err)
	}

	var unmarshaled models.AuditLog
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Errorf("Unmarshal() should handle empty EventData: %v", err)
	}
}

func TestLogCategoryConstants_AllUnique(t *testing.T) {
	categories := []string{
		models.LogCategorySystem,
		models.LogCategorySecurity,
		models.LogCategoryAgent,
		models.LogCategoryNetwork,
		models.LogCategoryStorage,
		models.LogCategoryUser,
		models.LogCategoryPolicy,
		models.LogCategoryRemote,
	}

	seen := make(map[string]bool)
	for _, cat := range categories {
		if seen[cat] {
			t.Errorf("Duplicate log category: %s", cat)
		}
		seen[cat] = true
	}
}

func TestAuditLog_JSONMarshaling_WithSpecialChars(t *testing.T) {
	log := models.AuditLog{
		Timestamp:    "2024-01-01T00:00:00Z",
		AgentID:      "test-agent-id-!@#$%",
		DeviceID:     "test-device-id-^&*()",
		LogCategory:  models.LogCategorySystem,
		EventType:    "boot",
		OSType:       "linux",
		AgentVersion: "v1.0.0",
		Severity:     "info",
		Source:       "systemd",
		EventData:    json.RawMessage(`{"test": "data with \"quotes\""}`),
	}

	data, err := json.Marshal(log)
	if err != nil {
		t.Errorf("Marshal() with special chars failed: %v", err)
	}

	var unmarshaled models.AuditLog
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Errorf("Unmarshal() with special chars failed: %v", err)
	}
}

func TestAuditLog_VeryLongFields(t *testing.T) {
	longString := string(make([]byte, 1000))
	for i := range longString {
		longString = longString[:i] + "a" + longString[i+1:]
	}

	log := models.AuditLog{
		Timestamp:    "2024-01-01T00:00:00Z",
		AgentID:      longString,
		DeviceID:     longString,
		LogCategory:  models.LogCategorySystem,
		EventType:    "boot",
		OSType:       "linux",
		AgentVersion: longString,
		Severity:     longString,
		Source:       longString,
		EventData:    json.RawMessage(`{"test": "data"}`),
	}

	data, err := json.Marshal(log)
	if err != nil {
		t.Errorf("Marshal() with long fields failed: %v", err)
	}

	var unmarshaled models.AuditLog
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Errorf("Unmarshal() with long fields failed: %v", err)
	}
}

func TestAuditLog_EventData_ValidJSON(t *testing.T) {
	log := models.AuditLog{
		Timestamp:    "2024-01-01T00:00:00Z",
		AgentID:      testAgentID,
		DeviceID:     testDeviceID,
		LogCategory:  models.LogCategorySystem,
		EventType:    "boot",
		OSType:       "linux",
		AgentVersion: "v1.0.0",
		Severity:     "info",
		Source:       "systemd",
		EventData:    json.RawMessage(`{"key": "value"}`),
	}

	data, err := json.Marshal(log)
	if err != nil {
		t.Errorf("Marshal() with valid JSON in EventData failed: %v", err)
	}
	_ = data
}
