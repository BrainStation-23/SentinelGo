package ram

import (
	"testing"
)

func TestSmbiosTypeToString(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{35, "LPDDR5"},
		{34, "DDR5"},
		{33, "HBM2"},
		{32, "HBM"},
		{30, "LPDDR4"},
		{29, "LPDDR3"},
		{28, "LPDDR2"},
		{27, "LPDDR"},
		{26, "DDR4"},
		{24, "DDR3"},
		{22, "DDR2 FB-DIMM"},
		{21, "DDR2"},
		{20, "DDR"},
		{17, "SDRAM"},
		// Unknown codes
		{99, "Unknown"},
		{0, "Unknown"},
		{1, "Unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			got := smbiosTypeToString(tc.code)
			if got != tc.want {
				t.Errorf("smbiosTypeToString(%d) = %q, want %q", tc.code, got, tc.want)
			}
		})
	}
}

func TestWindowsFormFactor(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{8, "DIMM"},
		{12, "SO-DIMM"},
		{13, "Micro-DIMM"},
		{7, "SIMM"},
		{15, "SIMM"},
		{14, "RIMM"},
		{0, ""},
		{99, ""},
		{1, ""},
	}

	for _, tc := range tests {
		got := windowsFormFactor(tc.code)
		if got != tc.want {
			t.Errorf("windowsFormFactor(%d) = %q, want %q", tc.code, got, tc.want)
		}
	}
}

func TestGetRAMs_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	info := Get()
	if len(info.RAMs) == 0 {
		t.Fatal("Get() returned no RAM sticks")
	}
	for i, stick := range info.RAMs {
		if stick.Capacity == 0 {
			t.Errorf("RAM stick %d has zero Capacity", i)
		}
		if stick.ArchitectureType == "" {
			t.Errorf("RAM stick %d has empty ArchitectureType", i)
		}
		t.Logf("stick[%d]: %+v", i, stick)
	}
}
