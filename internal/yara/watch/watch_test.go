//go:build windows || darwin || linux

package watch

import (
	"os"
	"os/exec"
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
	src := filepath.Join(outside, "moved.bin")
	if err := os.WriteFile(src, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(root, "moved.bin")
	writeAndMove(t, written, src, moved)

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

// writeAndMove writes written and renames src to moved from another
// process: the watchers ignore the agent's own writes (FSEvents'
// IgnoreSelf, the fanotify pid check).
func writeAndMove(t *testing.T, written, src, moved string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		if err := os.WriteFile(written, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(src, moved); err != nil {
			t.Skipf("rename across temp folders: %v", err)
		}
		return
	}
	cmd := exec.Command("/bin/sh", "-c", `printf x > "$1" && mv "$2" "$3"`, "sh", written, src, moved)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("writer process: %v: %s", err, out)
	}
}
