//go:build windows || darwin || linux

package watch

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// A file written into a watched folder (and one renamed into it) is
// reported. Linux needs CAP_SYS_ADMIN for fanotify: run as root.
func TestStart_ReportsWrites(t *testing.T) {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		t.Skip("fanotify needs root")
	}
	root := t.TempDir()
	if real, err := filepath.EvalSymlinks(root); err == nil {
		root = real // macOS: /var -> /private/var, which FSEvents reports
	}
	outside := t.TempDir()
	seen := make(chan string, 256)
	w, err := Start([]string{root}, Handler{Changed: func(p string) {
		select {
		case seen <- p:
		default:
		}
	}})
	if err != nil {
		if w == nil {
			t.Skipf("no watcher on this machine: %v", err)
		}
		t.Logf("partial: %v", err)
	}
	defer w.Close()
	time.Sleep(300 * time.Millisecond) // FSEvents starts asynchronously

	written := filepath.Join(root, "sub", "written.bin")
	if err := os.MkdirAll(filepath.Dir(written), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(written, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(outside, "moved.bin")
	if err := os.WriteFile(src, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(root, "moved.bin")
	if err := os.Rename(src, moved); err != nil {
		t.Skipf("rename across temp folders: %v", err)
	}

	want := map[string]bool{written: false, moved: false}
	deadline := time.After(10 * time.Second)
	for !want[written] || !want[moved] {
		select {
		case p := <-seen:
			for k := range want {
				if strings.EqualFold(p, k) {
					want[k] = true
				}
			}
		case <-deadline:
			t.Fatalf("not reported: %v", want)
		}
	}
}

func TestStart_NoRoots(t *testing.T) {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		t.Skip("fanotify needs root")
	}
	if w, err := Start(nil, Handler{}); w != nil || err == nil {
		t.Fatalf("Start(nil) = %v, %v", w, err)
	}
}
