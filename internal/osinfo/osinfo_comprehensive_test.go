package osinfo_test

import (
	"testing"
)

func TestCollect_BasicFields(t *testing.T) {
	info := collectForTest(t)
	if info == nil {
		t.Fatal("Collect() returned nil")
		return
	}

	// Verify basic fields are populated
	if info.Hostname == "" {
		t.Error("Collect() should set Hostname")
	}

	if info.Timestamp.IsZero() {
		t.Error("Collect() should set Timestamp")
	}
}

func TestCollect_CPUInfo(t *testing.T) {
	info := collectForTest(t)
	if info == nil {
		t.Fatal("Collect() returned nil")
		return
	}

	if info.CPU.ModelName == "" {
		t.Error("Collect() should set CPU ModelName")
	}

	if info.CPU.Cores == 0 {
		t.Error("Collect() should set CPU Cores")
	}
}

func TestCollect_MemoryInfo(t *testing.T) {
	info := collectForTest(t)
	if info == nil {
		t.Fatal("Collect() returned nil")
		return
	}

	if info.Memory.Total == 0 {
		t.Error("Collect() should set Memory Total")
	}
}

func TestCollect_DiskInfo(t *testing.T) {
	info := collectForTest(t)
	if info == nil {
		t.Fatal("Collect() returned nil")
		return
	}

	if info.Disk.Total == 0 {
		t.Error("Collect() should set Disk Total")
	}
}

func TestCollect_OSInfo(t *testing.T) {
	info := collectForTest(t)
	if info == nil {
		t.Fatal("Collect() returned nil")
		return
	}

	if info.OSInformation.OSName == "" {
		t.Error("Collect() should set OS Name")
	}
}

func TestCollect_NetworkInfo(t *testing.T) {
	info := collectForTest(t)
	if info == nil {
		t.Fatal("Collect() returned nil")
		return
	}

	if len(info.NetworkAdapters) == 0 {
		t.Error("Collect() should set Network Adapters")
	}
}
