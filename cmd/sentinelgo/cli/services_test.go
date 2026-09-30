package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"sentinelgo/internal/models"
)

// ── showServicesList ─────────────────────────────────────────────────────────

func TestShowServicesList_Empty(t *testing.T) {
	out := captureStdout(func() { showServicesList(nil) })
	if !strings.Contains(out, "Found 0 services") {
		t.Errorf("output = %q, want it to contain %q", out, "Found 0 services")
	}
}

func TestShowServicesList_GroupsBySourceAndPrintsFields(t *testing.T) {
	list := []models.ServiceInfo{
		{Name: "sshd", DisplayName: "SSH Daemon", Status: "running", StartType: "auto", Description: "secure shell", Source: "systemd", PID: 123, RunAs: "root"},
		{Name: "cron", Status: "running", StartType: "auto", Source: "systemd"},
		{Name: "com.apple.finder", Status: "running", StartType: "auto", Source: "launchd"},
	}
	out := captureStdout(func() { showServicesList(list) })

	if !strings.Contains(out, "Found 3 services") {
		t.Errorf("output missing service count; got %q", out)
	}
	if !strings.Contains(out, "SYSTEMD (2 items)") {
		t.Errorf("output missing systemd group header; got %q", out)
	}
	if !strings.Contains(out, "LAUNCHD (1 items)") {
		t.Errorf("output missing launchd group header; got %q", out)
	}
	if !strings.Contains(out, "Display: SSH Daemon") {
		t.Errorf("output missing display name; got %q", out)
	}
	if !strings.Contains(out, "PID: 123") {
		t.Errorf("output missing PID; got %q", out)
	}
	if !strings.Contains(out, "RunAs: root") {
		t.Errorf("output missing RunAs; got %q", out)
	}
	// cron has no DisplayName/Description/PID/RunAs set — those lines must be omitted.
	if strings.Contains(out, "PID: 0") {
		t.Errorf("output should omit PID line when PID <= 0; got %q", out)
	}
}

// ── printServiceItem ─────────────────────────────────────────────────────────

func TestPrintServiceItem_OmitsDisplayWhenSameAsName(t *testing.T) {
	svc := models.ServiceInfo{Name: "cron", DisplayName: "cron", Status: "running", StartType: "auto"}
	out := captureStdout(func() { printServiceItem(1, svc) })
	if strings.Contains(out, "Display:") {
		t.Errorf("output should omit Display line when DisplayName == Name; got %q", out)
	}
}

func TestPrintServiceItem_IncludesDescriptionWhenPresent(t *testing.T) {
	svc := models.ServiceInfo{Name: "sshd", Description: "secure shell daemon", Status: "running", StartType: "auto"}
	out := captureStdout(func() { printServiceItem(1, svc) })
	if !strings.Contains(out, "Desc: secure shell daemon") {
		t.Errorf("output missing description; got %q", out)
	}
}

// ── outputServicesJSON ───────────────────────────────────────────────────────

func TestOutputServicesJSON_EmptyList(t *testing.T) {
	out := captureStdout(func() { outputServicesJSON(nil) })
	var decoded []models.ServiceInfo
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, out)
	}
	if len(decoded) != 0 {
		t.Errorf("decoded = %v, want empty slice", decoded)
	}
}

func TestOutputServicesJSON_RoundTrips(t *testing.T) {
	list := []models.ServiceInfo{{Name: "sshd", Status: "running", Source: "systemd"}}
	out := captureStdout(func() { outputServicesJSON(list) })

	var decoded []models.ServiceInfo
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, out)
	}
	if len(decoded) != 1 || decoded[0].Name != "sshd" {
		t.Errorf("decoded = %+v, want a single sshd entry", decoded)
	}
}

// ── HandleServicesListCommand ────────────────────────────────────────────────

func TestHandleServicesListCommand_JSONMode(t *testing.T) {
	out := captureStdout(func() { HandleServicesListCommand("/nonexistent/config.json", true, false) })
	var decoded []models.ServiceInfo
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("JSON mode output not valid JSON: %v\noutput: %s", err, out)
	}
}

func TestHandleServicesListCommand_CountMode(t *testing.T) {
	out := captureStdout(func() { HandleServicesListCommand("/nonexistent/config.json", false, true) })
	if !strings.Contains(out, "Total services:") {
		t.Errorf("count mode output = %q, want it to contain %q", out, "Total services:")
	}
}

func TestHandleServicesListCommand_TableMode(t *testing.T) {
	out := captureStdout(func() { HandleServicesListCommand("/nonexistent/config.json", false, false) })
	if !strings.Contains(out, "Found") || !strings.Contains(out, "services:") {
		t.Errorf("table mode output = %q, want it to contain a \"Found N services\" header", out)
	}
}
