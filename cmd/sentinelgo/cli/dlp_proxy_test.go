package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The proxy must never listen where the network can reach it.
func TestRequireLoopback(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:3129": true, "[::1]:3129": true, "localhost:3129": true,
		"0.0.0.0:3129": false, ":3129": false, "10.0.0.5:3129": false, "example.com:3129": false, "3129": false,
	} {
		if err := requireLoopback(addr); (err == nil) != ok {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

func TestResetDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spill")
	if err := resetDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "upload-left-by-a-crash"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := resetDir(dir); err != nil {
		t.Fatal(err)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Errorf("left: %v", left)
	}
	if fi, _ := os.Stat(dir); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o700 { // Windows: an ACL (winsec)
		t.Errorf("mode %v", fi.Mode())
	}
}

func TestRunDLPProxy_Flags(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runDLPProxy([]string{}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "-hosts is required") {
		t.Errorf("no hosts: %d %q", code, errOut.String())
	}
	errOut.Reset()
	if code := runDLPProxy([]string{"-hosts", "a.example", "-listen", "0.0.0.0:3129"}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "loopback") {
		t.Errorf("open listen: %d %q", code, errOut.String())
	}
}
