package osinfo_test

import (
	"testing"
)

func TestGetLocalUsers(t *testing.T) {
	sysInfo := collectForTest(t)

	// Test that LocalUsers slice is not nil
	if sysInfo.LocalUsers == nil {
		t.Error("LocalUsers slice should not be nil")
	}

	// Test that we found some users (at least one should exist on most systems)
	if len(sysInfo.LocalUsers) == 0 {
		t.Log("No local users found - this might be expected on some systems")
	} else {
		t.Logf("Found %d local users: %v", len(sysInfo.LocalUsers), sysInfo.LocalUsers)
	}

	// Test that usernames are not empty strings
	for i, user := range sysInfo.LocalUsers {
		if user.Username == "" {
			t.Errorf("LocalUsers[%d] should not have empty username", i)
		}
	}
}

func TestSystemInfoCollection(t *testing.T) {
	sysInfo := collectForTest(t)

	// Test basic system info fields
	if sysInfo.Hostname == "" {
		t.Error("Hostname should not be empty")
	}

	if sysInfo.SerialNumber == "" {
		t.Error("SerialNumber should not be empty")
	}

	if sysInfo.OSQueryVersion == "" {
		t.Error("OSQueryVersion should not be empty")
	}

	if sysInfo.BatteryCondition == "" {
		t.Error("BatteryCondition should not be empty")
	}

	// Log collected information for verification
	t.Logf("Hostname: %s", sysInfo.Hostname)
	t.Logf("Serial Number: %s", sysInfo.SerialNumber)
	t.Logf("OSQuery Version: %s", sysInfo.OSQueryVersion)
	t.Logf("Battery Condition: %s", sysInfo.BatteryCondition)
	t.Logf("Local Users: %v", sysInfo.LocalUsers)
	t.Logf("CPU Model: %s", sysInfo.CPU.ModelName)
	t.Logf("CPU Cores: %d", sysInfo.CPU.Cores)
	t.Logf("Uptime: %d seconds", sysInfo.Uptime)
}

func TestAgentInfoPayload(t *testing.T) {
	sysInfo := collectForTest(t)

	// Create agent update payload similar to heartbeat
	agentUpdate := map[string]interface{}{
		"serial_number":     sysInfo.SerialNumber,
		"osquery_version":   sysInfo.OSQueryVersion,
		"battery_condition": sysInfo.BatteryCondition,
		"local_users":       sysInfo.LocalUsers,
		"Last restarted":    sysInfo.Uptime,
	}

	// Test that all required fields are present and not empty
	if agentUpdate["serial_number"] == "" {
		t.Error("serial_number should not be empty")
	}

	if agentUpdate["osquery_version"] == "" {
		t.Error("osquery_version should not be empty")
	}

	if agentUpdate["battery_condition"] == "" {
		t.Error("battery_condition should not be empty")
	}

	if agentUpdate["local_users"] == nil {
		t.Error("local_users should not be nil")
	}

	// Log the payload for verification
	t.Logf("Agent Update Payload:")
	for key, value := range agentUpdate {
		t.Logf("  %s: %v", key, value)
	}
}
