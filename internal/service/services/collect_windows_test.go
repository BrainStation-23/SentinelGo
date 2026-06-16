package services

import "testing"

var windowsFixture = []byte(`[
  {"Name":"BITS","DisplayName":"Background Intelligent Transfer Service","State":"Running","StartMode":"Manual","Description":"Transfers files","ProcessId":1234,"StartName":"LocalSystem"},
  {"Name":"WSearch","DisplayName":"Windows Search","State":"Stopped","StartMode":"Auto","Description":"Indexes content","ProcessId":0,"StartName":"LocalSystem"},
  {"Name":"MapsBroker","DisplayName":"Downloaded Maps Manager","State":"Stopped","StartMode":"Disabled","Description":"","ProcessId":0,"StartName":"NT AUTHORITY\\LocalService"}
]`)

func TestParseWindowsServiceOutput_count(t *testing.T) {
	svcs := parseWindowsServiceOutput(windowsFixture)
	if len(svcs) != 3 {
		t.Fatalf("want 3 services, got %d", len(svcs))
	}
}

func TestParseWindowsServiceOutput_fields(t *testing.T) {
	svcs := parseWindowsServiceOutput(windowsFixture)

	bits := svcs[0]
	if bits.Name != "BITS" {
		t.Errorf("Name = %q, want BITS", bits.Name)
	}
	if bits.Status != "running" {
		t.Errorf("Status = %q, want running", bits.Status)
	}
	if bits.PID != 1234 {
		t.Errorf("PID = %d, want 1234", bits.PID)
	}
	if bits.Source != "windows_services" {
		t.Errorf("Source = %q, want windows_services", bits.Source)
	}

	wsearch := svcs[1]
	if wsearch.Status != "stopped" {
		t.Errorf("WSearch Status = %q, want stopped", wsearch.Status)
	}
	if wsearch.StartType != "automatic" {
		t.Errorf("WSearch StartType = %q, want automatic", wsearch.StartType)
	}

	maps := svcs[2]
	if maps.StartType != "disabled" {
		t.Errorf("MapsBroker StartType = %q, want disabled", maps.StartType)
	}
	if maps.RunAs != `NT AUTHORITY\LocalService` {
		t.Errorf("MapsBroker RunAs = %q", maps.RunAs)
	}
}

// PowerShell emits a single JSON object (not an array) when exactly one service matches.
func TestParseWindowsServiceOutput_singleObject(t *testing.T) {
	single := []byte(`{"Name":"Spooler","DisplayName":"Print Spooler","State":"Running","StartMode":"Auto","Description":"","ProcessId":888,"StartName":"LocalSystem"}`)
	svcs := parseWindowsServiceOutput(single)
	if len(svcs) != 1 {
		t.Fatalf("want 1 service, got %d", len(svcs))
	}
	if svcs[0].Name != "Spooler" {
		t.Errorf("Name = %q, want Spooler", svcs[0].Name)
	}
}

func TestParseWindowsServiceOutput_invalidJSON(t *testing.T) {
	svcs := parseWindowsServiceOutput([]byte("not json"))
	if svcs != nil {
		t.Errorf("expected nil on bad JSON, got %v", svcs)
	}
}

func TestNormalizeWindowsState(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Running", "running"},
		{"Stopped", "stopped"},
		{"Paused", "paused"},
		{"Start Pending", "starting"},
		{"Stop Pending", "stopping"},
		{"", "unknown"},
		{"SomeOther", "someother"},
	}
	for _, c := range cases {
		if got := normalizeWindowsState(c.in); got != c.want {
			t.Errorf("normalizeWindowsState(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeWindowsStartMode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Auto", "automatic"},
		{"Manual", "manual"},
		{"Disabled", "disabled"},
		{"Boot", "boot"},
		{"System", "system"},
		{"", "unknown"},
	}
	for _, c := range cases {
		if got := normalizeWindowsStartMode(c.in); got != c.want {
			t.Errorf("normalizeWindowsStartMode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
