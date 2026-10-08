//go:build windows

package gpu

// Fuzz target for the Win32_VideoController JSON parser.
//
// The seed corpus runs as an ordinary unit test under `go test ./...` (Windows).
// To fuzz: go test -run='^$' -fuzz='^FuzzWindowsGPUJSON$' -fuzztime=1m ./internal/osinfo/gpu/

import (
	"strings"
	"testing"
)

func FuzzWindowsGPUJSON(f *testing.F) {
	for _, s := range []string{
		`{"Name":"NVIDIA GeForce RTX 3080","AdapterCompatibility":"NVIDIA","AdapterRAM":4293918720,"VideoMemoryType":2,"Status":"OK"}`,
		`[{"Name":"Intel(R) UHD Graphics","AdapterRAM":1073741824,"VideoMemoryType":4}]`,
		`{"Name":"x","AdapterRAM":-1}`, `{"Name":"x","AdapterRAM":1e300}`, `{"Name":"x","VideoMemoryType":-1e300}`,
		`[null]`, `null`, `[]`, `{`, ``,
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		for _, item := range parseWindowsGPUJSON(s) {
			g := parseWindowsGPUItem(item)
			if strings.HasPrefix(g.DedicatedVRAM, "-") || strings.HasPrefix(g.SharedVRAM, "-") {
				t.Fatalf("negative VRAM: dedicated=%q shared=%q", g.DedicatedVRAM, g.SharedVRAM)
			}
		}
	})
}
