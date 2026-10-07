//go:build linux

package gpu

// Fuzz targets for the Linux GPU parsers (lspci -nn / lspci -v output).
//
// The seed corpus runs as an ordinary unit test under `go test ./...` (Linux).
// To fuzz: go test -run='^$' -fuzz='^FuzzLspciLine$' -fuzztime=1m ./internal/osinfo/gpu/

import "testing"

func FuzzLspciLine(f *testing.F) {
	for _, s := range []string{
		"01:00.0 VGA compatible controller [0300]: NVIDIA Corporation GA102 [GeForce RTX 3080] [10de:2206] (rev a1)",
		"00:02.0 VGA compatible controller [0300]: Intel Corporation Alder Lake-P GT2 [8086:46a6] (rev 0c)",
		"\tMemory at 6000000000 (64-bit, prefetchable) [size=8G]",
		"\tMemory at e0000000 (64-bit, prefetchable) [size=",
		"prefetchable [size=]",
		"\tKernel driver in use: nvidia",
		"Kernel driver in use:",
		"01:00.0 VGA: [",
		"01:00.0 VGA: ]",
		"01:00.0 VGA: [] (rev ",
		"",
		"   ",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		_, _ = parseLspciLine(line)
		if size, ok := extractPrefetchableSize(line); ok {
			_ = parsePCISize(size)
		}
		_, _ = extractKernelDriver(line)
	})
}

func FuzzParsePCISize(f *testing.F) {
	for _, s := range []string{
		"512K", "256M", "8G", "1024", "", "abc", "  128M  ",
		"-1G", "9223372036854775807", "9223372036854775807K", "8589934592G", "G", "-", "+5M",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		if n := parsePCISize(s); n < 0 {
			t.Fatalf("parsePCISize(%q) = %d, want >= 0", s, n)
		}
	})
}

// TestParsePCISize_RejectsOverflowAndNegative guards against sizes that used
// to overflow int64 (or were negative) and surfaced as negative VRAM.
func TestParsePCISize_RejectsOverflowAndNegative(t *testing.T) {
	for _, s := range []string{"-1G", "-512K", "9223372036854775807K", "8589934592G"} {
		if got := parsePCISize(s); got != 0 {
			t.Errorf("parsePCISize(%q) = %d, want 0", s, got)
		}
	}
	if got := parsePCISize("8589934591G"); got != 8589934591*(1<<30) {
		t.Errorf("parsePCISize(largest valid G) = %d", got)
	}
}

func TestParseLspciLine_Empty(t *testing.T) {
	for _, line := range []string{"", "   "} {
		if busID, _ := parseLspciLine(line); busID != "" {
			t.Errorf("parseLspciLine(%q) busID = %q, want empty", line, busID)
		}
	}
}
