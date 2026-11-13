package filedlp

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestVolumesOf(t *testing.T) {
	vols, network := volumesOf([]string{`C:\Users\ana\Documents`, `c:\Users\bo\Desktop`, `D:\Shared`, `\\server\share\x`})
	if !slices.Equal(vols, []string{"C:", "D:"}) || !network {
		t.Fatalf("vols %v network %v", vols, network)
	}
}

// The real journal of the temp folder's volume: a file written after Mark
// is reported by Changes. Run elevated: go test -run TestUSNJournal_Real
// ./internal/dlp/filedlp/
func TestUSNJournal_Real(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated prompt: reading the change journal needs admin")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	roots := []string{dir}
	j := newUSNJournal()
	defer j.Close()
	cursors := j.Mark(roots, nil)
	vol := strings.ToUpper(filepath.VolumeName(dir))
	if st := j.States()[vol]; st != "active" {
		t.Skipf("no journal on %s: %s", vol, st)
	}

	p := filepath.Join(dir, "written.txt")
	if err := os.WriteFile(p, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths, next, lost := j.Changes(context.Background(), roots, cursors)
	if lost {
		t.Fatal("the journal lost track")
	}
	found := false
	for _, q := range paths {
		if strings.EqualFold(q, p) {
			found = true
		}
	}
	if !found {
		t.Fatalf("%s not in %q", p, paths)
	}
	if next[vol].Next <= cursors[vol].Next {
		t.Fatalf("cursor didn't move: %+v → %+v", cursors[vol], next[vol])
	}

	// Read from there: nothing new.
	paths, _, lost = j.Changes(context.Background(), roots, next)
	for _, q := range paths {
		if strings.EqualFold(q, p) {
			t.Fatalf("reported again: %q (lost %v)", paths, lost)
		}
	}

	// A cursor from another journal means walk again.
	if _, _, lost := j.Changes(context.Background(), roots, map[string]JournalCursor{vol: {Journal: 1, Next: 0}}); !lost {
		t.Fatal("a stale cursor should be lost")
	}
}
