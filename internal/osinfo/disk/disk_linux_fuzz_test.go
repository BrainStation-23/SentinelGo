//go:build linux

package disk

// Fuzz target for the lsblk partition-line parser.
//
// The seed corpus runs as an ordinary unit test under `go test ./...` (Linux).
// To fuzz: go test -run='^$' -fuzz='^FuzzParsePartitionLine$' -fuzztime=1m ./internal/osinfo/disk/

import (
	"strings"
	"testing"
)

func FuzzParsePartitionLine(f *testing.F) {
	for _, s := range []string{"ext4 /", "vfat /boot/efi", "   /boot/efi", "swap", "", "a b c", "\t\n"} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		fs, mount := parsePartitionLine(line)
		if fs != "" && mount == "" {
			t.Fatalf("parsePartitionLine(%q) = (%q, %q): filesystem without a mount point", line, fs, mount)
		}
		if fs == "" && mount != "" && len(strings.Fields(line)) == 1 && !strings.HasPrefix(mount, "/") {
			t.Fatalf("parsePartitionLine(%q) returned non-absolute mount %q", line, mount)
		}
	})
}
