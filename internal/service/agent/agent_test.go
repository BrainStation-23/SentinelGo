package agent_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/osinfo/shared"
	"sentinelgo/internal/service/agent"
)

// assertNoNUL fails the test unless body is valid JSON with no encoded NUL escape.
func assertNoNUL(t *testing.T, body []byte) {
	t.Helper()
	if len(body) == 0 {
		t.Fatal("server captured no request body")
	}
	if !json.Valid(body) {
		t.Fatalf("request body is not valid JSON: %q", body)
	}
	if strings.Contains(string(body), "\\u0000") {
		t.Fatalf("request body still contains an encoded NUL escape: %q", body)
	}
}

func mockSysInfo() *shared.SystemInfo {
	return &shared.SystemInfo{
		Hostname:   "test-host",
		MACAddress: "00:11:22:33:44:55",
		CPU: shared.CPUInfo{
			ModelName: "Intel(R) Core(TM) i7",
			Cores:     8,
			Usage:     12.5,
		},
		Memory: shared.MemoryInfo{
			Total: 16 * 1024 * 1024 * 1024,
			Used:  8 * 1024 * 1024 * 1024,
		},
		Disk: shared.DiskInfo{
			Total: 512 * 1024 * 1024 * 1024,
			Used:  128 * 1024 * 1024 * 1024,
			Free:  384 * 1024 * 1024 * 1024,
		},
		LocalUsers: []shared.UserWithGroup{
			{Username: "admin", Groups: []string{"sudo", "admin"}, UID: "1000", GID: "1000"},
			{Username: "testuser", Groups: []string{"users"}, UID: "1001", GID: "1001"},
		},
		SerialNumber:     "TEST-SERIAL-123",
		HardwareModel:    "TestModel",
		OSQueryVersion:   "5.0.0",
		BatteryCondition: "Good",
		FQDN:             "test-host.example.com",
		ChassisType:      "Desktop",
		KernelVersion:    "5.15.0",
		RAMs:             shared.RAMInfo{},
		Disks:            []shared.DiskDevice{},
		FirmwareType:     "BIOS",
		FirmwareVendor:   "TestVendor",
		FirmwareVersion:  "1.0.0",
		NetworkAdapters:  []shared.NetAdapter{},
		Peripherals:      []shared.PeripheralDevice{},
		Displays:         []shared.Display{},
		CPUInfoDetailed: shared.CPUInfoDetailed{
			Processor:          "Intel(R) Core(TM) i7",
			ClockSpeed:         "3000 MHz",
			NumberCores:        8,
			NumberLogicalCores: 16,
			ArchitectureType:   "x64",
			Manufacturer:       "Intel",
		},
		AudioDevices:  []shared.AudioDevice{},
		Printers:      []shared.Printer{},
		OSInformation: shared.OSInformation{},
	}
}

func TestNewAgentService(t *testing.T) {
	svc := agent.NewAgentService()
	if svc == nil {
		t.Fatal("NewAgentService() returned nil")
	}
}

func TestNewAgentService_IndependentInstances(t *testing.T) {
	svc1 := agent.NewAgentService()
	svc2 := agent.NewAgentService()
	if svc1 == nil || svc2 == nil {
		t.Fatal("NewAgentService() returned nil")
	}
	if svc1 == svc2 {
		t.Error("NewAgentService() should return independent instances, not a singleton")
	}
}

func TestUpdateAgentInfo(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	cfg := &config.Config{
		SupabaseURL: server.URL,
		AccessToken: "test-token",
		DeviceID:    "dev-1",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	agentSvc := agent.NewAgentService()
	if err := agentSvc.UpdateAgentInfo(ctx, cfg, mockSysInfo()); err != nil {
		t.Fatalf("UpdateAgentInfo failed against mock server: %v", err)
	}
	if hits == 0 {
		t.Error("expected UpdateAgentInfo to call the Supabase endpoint")
	}
}

func TestUpdateAgentInfo_StripsNUL(t *testing.T) {
	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	cfg := &config.Config{SupabaseURL: server.URL, AccessToken: "test-token", DeviceID: "dev-1"}

	// Inject NUL bytes into collected inventory fields; they must not reach the wire.
	sysInfo := mockSysInfo()
	sysInfo.Hostname = "host\x00name"
	sysInfo.SerialNumber = "SER\x00IAL"
	sysInfo.KernelVersion = "5.15\x000"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := agent.NewAgentService().UpdateAgentInfo(ctx, cfg, sysInfo); err != nil {
		t.Fatalf("UpdateAgentInfo: %v", err)
	}
	assertNoNUL(t, body)
}

func TestUpdateAgentInfo_CancelledContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.Config{SupabaseURL: server.URL, AccessToken: "test-token", DeviceID: "dev-1"}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := agent.NewAgentService().UpdateAgentInfo(ctx, cfg, mockSysInfo()); err == nil {
		t.Error("expected error with cancelled context, got nil")
	}
}

func TestSetAgentStatus_Success(t *testing.T) {
	var receivedMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	cfg := &config.Config{
		SupabaseURL: server.URL,
		SupabaseKey: "test-key",
		AccessToken: "test-token",
		DeviceID:    "test-device",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	svc := agent.NewAgentService()
	if err := svc.SetAgentStatus(ctx, cfg, "online"); err != nil {
		t.Fatalf("SetAgentStatus failed: %v", err)
	}
	if receivedMethod != http.MethodPatch {
		t.Errorf("expected PATCH request, got %s", receivedMethod)
	}
}

func TestGetAgentInfo_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"device_id":"test-device","status":"online"}]`))
	}))
	defer server.Close()

	cfg := &config.Config{
		SupabaseURL: server.URL,
		SupabaseKey: "test-key",
		AccessToken: "test-token",
		DeviceID:    "test-device",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	info, err := agent.NewAgentService().GetAgentInfo(ctx, cfg)
	if err != nil {
		t.Fatalf("GetAgentInfo failed: %v", err)
	}
	if info == nil {
		t.Fatal("GetAgentInfo returned nil map")
	}
	if info["device_id"] != "test-device" {
		t.Errorf("device_id = %v, want test-device", info["device_id"])
	}
}

func TestGetAgentInfo_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	cfg := &config.Config{
		SupabaseURL: server.URL,
		SupabaseKey: "test-key",
		AccessToken: "test-token",
		DeviceID:    "test-device",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := agent.NewAgentService().GetAgentInfo(ctx, cfg)
	if err == nil {
		t.Fatal("expected error for empty agent list, got nil")
	}
}
