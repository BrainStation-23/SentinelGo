package emergencylog

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// resetForTest clears the package globals so each test starts uninitialized.
// The package is a process global, so tests must not run in parallel.
func resetForTest() {
	mu.Lock()
	dir = ""
	lastDay = ""
	mu.Unlock()
}

func todayFile(d string) string {
	day := time.Now().UTC().Format("2006-01-02")
	return filepath.Join(d, "emergency-"+day+".log")
}

func TestRecordBeforeInitIsNoOp(t *testing.T) {
	resetForTest()
	tmp := t.TempDir()
	// dir is unset, so nothing should be written anywhere and it must not panic.
	Record("startup", "should not write %d", 1)
	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no files written before Init, got %d", len(entries))
	}
}

func TestRecordFormat(t *testing.T) {
	resetForTest()
	tmp := t.TempDir()
	if err := Init(tmp); err != nil {
		t.Fatal(err)
	}

	Record("update", "boom %d", 3)

	data, err := os.ReadFile(todayFile(tmp))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d: %q", len(lines), lines)
	}

	re := regexp.MustCompile(`^\S+ EMERGENCY \[update\] boom 3$`)
	if !re.MatchString(lines[0]) {
		t.Fatalf("line did not match expected format: %q", lines[0])
	}

	ts := strings.Fields(lines[0])[0]
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		t.Fatalf("timestamp is not RFC3339: %q (%v)", ts, err)
	}
	if !strings.HasSuffix(ts, "Z") {
		t.Fatalf("timestamp is not UTC (no trailing Z): %q", ts)
	}
}

func TestRecordSanitizesNewlines(t *testing.T) {
	resetForTest()
	tmp := t.TempDir()
	if err := Init(tmp); err != nil {
		t.Fatal(err)
	}

	// A message with embedded newlines must not forge extra lines.
	Record("auth", "line1\nINJECTED\rline2")

	data, err := os.ReadFile(todayFile(tmp))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected newlines stripped to 1 line, got %d: %q", len(lines), lines)
	}
}

func TestRecordAppends(t *testing.T) {
	resetForTest()
	tmp := t.TempDir()
	if err := Init(tmp); err != nil {
		t.Fatal(err)
	}

	Record("auth", "first")
	Record("auth", "second")

	data, err := os.ReadFile(todayFile(tmp))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), lines)
	}
	if !strings.Contains(lines[0], "first") {
		t.Fatalf("first line lost: %q", lines[0])
	}
	if !strings.Contains(lines[1], "second") {
		t.Fatalf("second line missing: %q", lines[1])
	}
}

func TestPruneRetention(t *testing.T) {
	resetForTest()
	tmp := t.TempDir()
	mu.Lock()
	dir = tmp
	mu.Unlock()

	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		keep bool
	}{
		{"emergency-2026-06-16.log", true},  // today
		{"emergency-2026-06-15.log", true},  // -1
		{"emergency-2026-06-14.log", true},  // -2 (oldest kept)
		{"emergency-2026-06-13.log", false}, // -3 (pruned)
		{"emergency-2026-06-11.log", false}, // -5 (pruned)
		{"emergency-notadate.log", true},    // unparseable -> left alone
		{"other.txt", true},                 // not ours -> left alone
	}
	for _, c := range cases {
		if err := os.WriteFile(filepath.Join(tmp, c.name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	mu.Lock()
	prune(now)
	mu.Unlock()

	for _, c := range cases {
		_, err := os.Stat(filepath.Join(tmp, c.name))
		exists := err == nil
		if exists != c.keep {
			t.Errorf("%s: exists=%v, want keep=%v", c.name, exists, c.keep)
		}
	}
}

func TestConcurrentWrites(t *testing.T) {
	resetForTest()
	tmp := t.TempDir()
	if err := Init(tmp); err != nil {
		t.Fatal(err)
	}

	const goroutines, perG = 50, 20
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < perG; j++ {
				Record("sync", "g%d-%d", id, j)
			}
		}(i)
	}
	wg.Wait()

	data, err := os.ReadFile(todayFile(tmp))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != goroutines*perG {
		t.Fatalf("expected %d lines, got %d", goroutines*perG, len(lines))
	}
	re := regexp.MustCompile(`^\S+ EMERGENCY \[sync\] g\d+-\d+$`)
	for _, l := range lines {
		if !re.MatchString(l) {
			t.Fatalf("malformed or torn line: %q", l)
		}
	}
}

func TestInitFailureDoesNotPanic(t *testing.T) {
	resetForTest()
	tmp := t.TempDir()

	// Create a regular file, then ask Init to create a directory underneath it.
	// MkdirAll must fail because a path component is a non-directory.
	fileAsParent := filepath.Join(tmp, "afile")
	if err := os.WriteFile(fileAsParent, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Init(filepath.Join(fileAsParent, "sub")); err == nil {
		t.Fatalf("expected Init to fail when a parent path component is a file")
	}

	// dir stays unset; Record must be a safe no-op (echo only), never panic.
	Record("startup", "after failed init")
}
