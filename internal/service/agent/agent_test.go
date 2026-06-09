package agent_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/osinfo/shared"
	"sentinelgo/internal/service/agent"
)

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
		TPMVersion:       "2.0",
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

func TestNewAgentService_Nil(t *testing.T) {
	svc := agent.NewAgentService()
	if svc == nil {
		t.Fatal("NewAgentService() returned nil")
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
