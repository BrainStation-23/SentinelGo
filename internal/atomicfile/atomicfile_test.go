package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	for _, content := range []string{"first", "second"} {
		if err := Write(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != content {
			t.Fatalf("read %q, %v; want %q", got, err, content)
		}
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temp files left behind: %v, %v", entries, err)
	}
}

func TestWriteFailsWithoutDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "state.json")
	if err := Write(path, []byte("x"), 0o600); err == nil {
		t.Fatal("wrote into a directory that doesn't exist")
	}
}
