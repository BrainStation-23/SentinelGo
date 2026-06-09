package cpu

// cpu_test.go validates that Get() returns a structurally sound Result on the
// current platform. The CPU-percent measurement inside collect() blocks for
// ~1 second, so the integration test is skipped in -short mode.

import (
	"runtime"
	"strings"
	"testing"
)

func TestGet_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CPU collection (1-second percent measurement) in -short mode")
	}

	r := Get()

	t.Logf("ModelName:          %q", r.Info.ModelName)
	t.Logf("Cores (logical):    %d", r.Info.Cores)
	t.Logf("Usage:              %.2f%%", r.Info.Usage)
	t.Logf("Processor:          %q", r.Detailed.Processor)
	t.Logf("ClockSpeed:         %q", r.Detailed.ClockSpeed)
	t.Logf("PhysicalCores:      %d", r.Detailed.NumberCores)
	t.Logf("LogicalCores:       %d", r.Detailed.NumberLogicalCores)
	t.Logf("ArchitectureType:   %q", r.Detailed.ArchitectureType)
	t.Logf("Manufacturer:       %q", r.Detailed.Manufacturer)

	if r.Info.ModelName == "" {
		t.Error("Info.ModelName is empty")
	}
	if r.Info.Cores <= 0 {
		t.Errorf("Info.Cores = %d, want > 0", r.Info.Cores)
	}
	if r.Info.Usage < 0 || r.Info.Usage > 100 {
		t.Errorf("Info.Usage = %.2f, want in [0, 100]", r.Info.Usage)
	}

	if r.Detailed.Processor == "" {
		t.Error("Detailed.Processor is empty")
	}
	if r.Detailed.NumberCores <= 0 {
		t.Errorf("Detailed.NumberCores = %d, want > 0", r.Detailed.NumberCores)
	}
	if r.Detailed.NumberLogicalCores < r.Detailed.NumberCores {
		t.Errorf("Detailed.NumberLogicalCores (%d) < NumberCores (%d)",
			r.Detailed.NumberLogicalCores, r.Detailed.NumberCores)
	}
	if r.Detailed.ArchitectureType == "" {
		t.Error("Detailed.ArchitectureType is empty")
	}
	if r.Detailed.ClockSpeed != "" && !strings.Contains(r.Detailed.ClockSpeed, "MHz") {
		t.Errorf("Detailed.ClockSpeed = %q, expected to contain 'MHz'", r.Detailed.ClockSpeed)
	}
}

func TestGet_ArchMatchesRuntime(t *testing.T) {
	r := Get()
	if r.Detailed.ArchitectureType != runtime.GOARCH {
		t.Errorf("Detailed.ArchitectureType = %q, want %q (runtime.GOARCH)",
			r.Detailed.ArchitectureType, runtime.GOARCH)
	}
}

func TestGet_InfoAndDetailedCoresConsistent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping CPU collection in -short mode")
	}
	r := Get()
	// Info.Cores is logical cores; Detailed.NumberLogicalCores must agree.
	if r.Info.Cores != r.Detailed.NumberLogicalCores {
		t.Errorf("Info.Cores (%d) != Detailed.NumberLogicalCores (%d)",
			r.Info.Cores, r.Detailed.NumberLogicalCores)
	}
	// Info.ModelName and Detailed.Processor are both sourced from the same
	// gopsutil ModelName field.
	if r.Info.ModelName != r.Detailed.Processor {
		t.Errorf("Info.ModelName (%q) != Detailed.Processor (%q)",
			r.Info.ModelName, r.Detailed.Processor)
	}
}
