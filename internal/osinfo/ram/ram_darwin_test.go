package ram

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

func TestGetRAMs_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	info := Get()
	if info.TotalCapacity == 0 {
		t.Fatal("Get() returned zero TotalCapacity")
	}
	t.Logf("TotalCapacity: %d bytes", info.TotalCapacity)
	for i, stick := range info.RAMs {
		if stick.Capacity == 0 {
			t.Errorf("RAM stick %d has zero Capacity", i)
		}
		t.Logf("stick[%d]: %+v", i, stick)
	}
}

const (
	gib8  uint64 = 8 * 1024 * 1024 * 1024
	gib16 uint64 = 16 * 1024 * 1024 * 1024

	darwinMemCmd    = "system_profiler SPMemoryDataType -json"
	darwinSysctlCmd = "sysctl -n hw.memsize"
)

// stubDarwinRAMCommand replaces darwinRunCommand for the duration of the test.
// Commands are keyed by "name arg1 arg2 ..."; keys in responses return their
// output and every other command fails. The returned pointer records every
// command that was run.
func stubDarwinRAMCommand(t *testing.T, responses map[string]string) *[]string {
	t.Helper()
	orig := darwinRunCommand
	var calls []string
	darwinRunCommand = func(name string, args ...string) (string, error) {
		key := strings.Join(append([]string{name}, args...), " ")
		calls = append(calls, key)
		if out, ok := responses[key]; ok {
			return out, nil
		}
		return "", errors.New("command failed: " + key)
	}
	t.Cleanup(func() { darwinRunCommand = orig })
	return &calls
}

func TestParseDarwinMemoryData(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantOK  bool
		wantLen int
	}{
		{"invalid JSON", "not json", false, 0},
		{"missing key", `{}`, false, 0},
		{"key is not an array", `{"SPMemoryDataType": "16 GB"}`, false, 0},
		{"empty array", `{"SPMemoryDataType": []}`, true, 0},
		{"two entries", `{"SPMemoryDataType": [{"_name": "a"}, {"_name": "b"}]}`, true, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseDarwinMemoryData(tc.input)
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}
			if len(got) != tc.wantLen {
				t.Errorf("len = %d, want %d", len(got), tc.wantLen)
			}
		})
	}
}

func TestParseIntelDIMM(t *testing.T) {
	tests := []struct {
		name      string
		input     map[string]any
		want      shared.RAMStick
		wantBytes uint64
		wantOK    bool
	}{
		{
			name: "populated DDR4 slot",
			input: map[string]any{
				"_name":       "DIMM0/0",
				"dimm_vendor": "0x80CE",
				"dimm_size":   "8 GB",
				"dimm_type":   "DDR4",
				"dimm_speed":  "2667 MHz",
				"dimm_status": "ok",
			},
			want: shared.RAMStick{
				Name: "DIMM0/0", Slot: "DIMM0/0", Manufacturer: "0x80CE",
				Capacity: gib8, ArchitectureType: "DDR4", ClockSpeedMHz: 2667,
			},
			wantBytes: gib8,
			wantOK:    true,
		},
		{
			name: "empty slot reports no size",
			input: map[string]any{
				"_name":       "DIMM1/0",
				"dimm_size":   "empty",
				"dimm_status": "empty",
				"dimm_type":   "empty",
				"dimm_speed":  "empty",
			},
			want: shared.RAMStick{
				Name: "DIMM1/0", Slot: "DIMM1/0", ArchitectureType: "empty",
			},
			wantBytes: 0,
			wantOK:    false,
		},
		{
			name:      "no fields at all",
			input:     map[string]any{},
			want:      shared.RAMStick{},
			wantBytes: 0,
			wantOK:    false,
		},
		{
			name: "non-string fields are ignored",
			input: map[string]any{
				"_name":     float64(1),
				"dimm_size": float64(8),
			},
			want:      shared.RAMStick{},
			wantBytes: 0,
			wantOK:    false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, gotBytes, ok := parseIntelDIMM(tc.input)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("stick = %+v, want %+v", got, tc.want)
			}
			if gotBytes != tc.wantBytes {
				t.Errorf("bytes = %d, want %d", gotBytes, tc.wantBytes)
			}
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}
		})
	}
}

func TestParseIntelMemoryGroup(t *testing.T) {
	items := []any{
		map[string]any{"_name": "DIMM0/0", "dimm_size": "8 GB", "dimm_type": "DDR4"},
		"not-a-map",
		map[string]any{"_name": "DIMM0/1", "dimm_size": "empty"},
		map[string]any{"_name": "DIMM1/0", "dimm_size": "8192 MB", "dimm_type": "DDR4"},
	}
	rams, total := parseIntelMemoryGroup(items)
	want := []shared.RAMStick{
		{Name: "DIMM0/0", Slot: "DIMM0/0", Capacity: gib8, ArchitectureType: "DDR4"},
		{Name: "DIMM1/0", Slot: "DIMM1/0", Capacity: gib8, ArchitectureType: "DDR4"},
	}
	if !reflect.DeepEqual(rams, want) {
		t.Errorf("rams = %+v, want %+v", rams, want)
	}
	if total != gib16 {
		t.Errorf("total = %d, want %d", total, gib16)
	}
}

func TestParseAppleSiliconMemory(t *testing.T) {
	tests := []struct {
		name      string
		input     map[string]any
		want      shared.RAMStick
		wantBytes uint64
		wantOK    bool
	}{
		{
			name: "typical Apple Silicon entry (size under SPMemoryDataType key)",
			input: map[string]any{
				"SPMemoryDataType":  "16 GB",
				"dimm_manufacturer": "Hynix",
				"dimm_type":         "LPDDR5",
			},
			want: shared.RAMStick{
				Name: "Unified Memory", FormFactor: "Unified", Manufacturer: "Hynix",
				Capacity: gib16, ArchitectureType: "LPDDR5",
			},
			wantBytes: gib16,
			wantOK:    true,
		},
		{
			name: "dimm_size takes precedence over SPMemoryDataType",
			input: map[string]any{
				"_name":            "Memory",
				"dimm_size":        "8 GB",
				"SPMemoryDataType": "16 GB",
				"dimm_speed":       "6400 MHz",
			},
			want: shared.RAMStick{
				Name: "Memory", FormFactor: "Unified", Capacity: gib8, ClockSpeedMHz: 6400,
			},
			wantBytes: gib8,
			wantOK:    true,
		},
		{
			name:  "no size information",
			input: map[string]any{"dimm_type": "LPDDR4X"},
			want: shared.RAMStick{
				Name: "Unified Memory", FormFactor: "Unified", ArchitectureType: "LPDDR4X",
			},
			wantBytes: 0,
			wantOK:    false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, gotBytes, ok := parseAppleSiliconMemory(tc.input)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("stick = %+v, want %+v", got, tc.want)
			}
			if gotBytes != tc.wantBytes {
				t.Errorf("bytes = %d, want %d", gotBytes, tc.wantBytes)
			}
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}
		})
	}
}

func TestParseMemoryProfilerData(t *testing.T) {
	memData := []any{
		"not-a-map",
		map[string]any{
			"_name": "Memory Slots",
			"_items": []any{
				map[string]any{"_name": "DIMM0/0", "dimm_size": "8 GB"},
				map[string]any{"_name": "DIMM1/0", "dimm_size": "8 GB"},
			},
		},
		// "_items" of the wrong type falls through to the unified-memory
		// parser, which finds no size and skips the entry.
		map[string]any{"_items": "oops"},
		map[string]any{"SPMemoryDataType": "16 GB"},
	}
	rams, total := parseMemoryProfilerData(memData)
	want := []shared.RAMStick{
		{Name: "DIMM0/0", Slot: "DIMM0/0", Capacity: gib8},
		{Name: "DIMM1/0", Slot: "DIMM1/0", Capacity: gib8},
		{Name: "Unified Memory", FormFactor: "Unified", Capacity: gib16},
	}
	if !reflect.DeepEqual(rams, want) {
		t.Errorf("rams = %+v, want %+v", rams, want)
	}
	if total != 2*gib16 {
		t.Errorf("total = %d, want %d", total, 2*gib16)
	}

	if rams, total := parseMemoryProfilerData(nil); rams != nil || total != 0 {
		t.Errorf("parseMemoryProfilerData(nil) = %+v, %d; want nil, 0", rams, total)
	}
}

func TestGetRAMs_DarwinAppleSilicon(t *testing.T) {
	calls := stubDarwinRAMCommand(t, map[string]string{
		darwinMemCmd: `{"SPMemoryDataType":[{"SPMemoryDataType":"16 GB","dimm_manufacturer":"Hynix","dimm_type":"LPDDR5"}]}`,
	})
	got := Get()
	want := shared.RAMInfo{
		TotalCapacity: gib16,
		RAMs: []shared.RAMStick{{
			Name: "Unified Memory", FormFactor: "Unified", Manufacturer: "Hynix",
			Capacity: gib16, ArchitectureType: "LPDDR5",
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Get() = %+v, want %+v", got, want)
	}
	// A size was found, so the sysctl fallback must not run.
	if !reflect.DeepEqual(*calls, []string{darwinMemCmd}) {
		t.Errorf("commands run = %q, want [%q]", *calls, darwinMemCmd)
	}
}

func TestGetRAMs_DarwinSysctlFallback(t *testing.T) {
	// All DIMM slots report "empty" so system_profiler yields no size.
	const emptySlots = `{"SPMemoryDataType":[{"_name":"Memory Slots","_items":[{"_name":"DIMM0/0","dimm_size":"empty"}]}]}`
	tests := []struct {
		name      string
		sysctl    *string
		wantTotal uint64
	}{
		{name: "sysctl reports bytes", sysctl: strPtr("17179869184\n"), wantTotal: gib16},
		{name: "sysctl output is not a number", sysctl: strPtr("hw.memsize: unknown\n"), wantTotal: 0},
		{name: "sysctl fails", sysctl: nil, wantTotal: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			responses := map[string]string{darwinMemCmd: emptySlots}
			if tc.sysctl != nil {
				responses[darwinSysctlCmd] = *tc.sysctl
			}
			calls := stubDarwinRAMCommand(t, responses)

			got := getRAMs()
			if got.TotalCapacity != tc.wantTotal {
				t.Errorf("TotalCapacity = %d, want %d", got.TotalCapacity, tc.wantTotal)
			}
			if len(got.RAMs) != 0 {
				t.Errorf("RAMs = %+v, want none", got.RAMs)
			}
			if !reflect.DeepEqual(*calls, []string{darwinMemCmd, darwinSysctlCmd}) {
				t.Errorf("commands run = %q, want [%q %q]", *calls, darwinMemCmd, darwinSysctlCmd)
			}
		})
	}
}

func TestGetRAMs_DarwinFailureModes(t *testing.T) {
	tests := []struct {
		name      string
		responses map[string]string
	}{
		{name: "system_profiler fails", responses: map[string]string{}},
		{name: "invalid JSON", responses: map[string]string{darwinMemCmd: "garbage"}},
		{name: "wrong shape", responses: map[string]string{darwinMemCmd: `{"SPMemoryDataType":{}}`}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := stubDarwinRAMCommand(t, tc.responses)
			if got := getRAMs(); !reflect.DeepEqual(got, shared.RAMInfo{}) {
				t.Errorf("getRAMs() = %+v, want zero value", got)
			}
			// Bails out before the sysctl fallback.
			if !reflect.DeepEqual(*calls, []string{darwinMemCmd}) {
				t.Errorf("commands run = %q, want [%q]", *calls, darwinMemCmd)
			}
		})
	}
}

func strPtr(s string) *string { return &s }
