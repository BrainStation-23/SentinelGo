package filedlp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"sentinelgo/internal/dlp/policy"
)

// writtenFile writes content at dir/name and returns a Request for it as the
// hook would: the file open read-only, its identity from fstat.
func writtenFile(t *testing.T, dir, name, content string) Request {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	return Request{File: f, Path: p, Ident: Identity{Dev: st.Dev, Ino: st.Ino, Size: st.Size}}
}

func TestRemediator(t *testing.T) {
	stick, cfg := t.TempDir(), t.TempDir()
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	m := &remediator{dir: filepath.Join(cfg, QuarantineDir), now: func() time.Time { return now }}

	// Quarantine: a copy in the root-only folder, the original gone.
	r := writtenFile(t, stick, "cards.csv", "4111 1111 1111 1111")
	if err := m.remediate(r, policy.ViolationQuarantine); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(r.Path); !os.IsNotExist(err) {
		t.Errorf("original still there: %v", err)
	}
	entries, _ := os.ReadDir(m.dir)
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), "-cards.csv") {
		t.Fatalf("quarantine %v", entries)
	}
	got, _ := os.ReadFile(filepath.Join(m.dir, entries[0].Name()))
	fi, _ := os.Stat(m.dir)
	qi, _ := entries[0].Info()
	if string(got) != "4111 1111 1111 1111" || fi.Mode().Perm() != 0o700 || qi.Mode().Perm() != 0o600 {
		t.Errorf("copy %q, folder %v, file %v", got, fi.Mode(), qi.Mode())
	}

	// Delete.
	r = writtenFile(t, stick, "keys.txt", "TOPSECRET")
	if err := m.remediate(r, policy.ViolationDelete); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(r.Path); !os.IsNotExist(err) {
		t.Errorf("not deleted: %v", err)
	}

	// A file swapped in after the scan is left alone, and the error doesn't
	// carry its path.
	r = writtenFile(t, stick, "salary_review_jane.xlsx", "old")
	if err := os.Remove(r.Path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.Path, []byte("someone else's file"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := m.remediate(r, policy.ViolationDelete)
	if err == nil || strings.Contains(err.Error(), "salary") {
		t.Errorf("swapped file: %v", err)
	}
	if b, _ := os.ReadFile(r.Path); string(b) != "someone else's file" {
		t.Error("the swapped-in file was touched")
	}

	// A full quarantine folder refuses, and keeps the original.
	big := writtenFile(t, stick, "big.bin", "x")
	big.Ident.Size = quarantineMaxBytes
	if err := m.remediate(big, policy.ViolationQuarantine); err == nil || !strings.Contains(err.Error(), "full") {
		t.Errorf("full: %v", err)
	}
	if _, err := os.Stat(big.Path); err != nil {
		t.Errorf("original removed although the quarantine failed: %v", err)
	}

	// Entries older than the keep period are pruned.
	old := filepath.Join(m.dir, "old-entry")
	if err := os.WriteFile(old, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	past := now.Add(-quarantineKeep - time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	m.prune()
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("old entry kept")
	}
}

func TestErrnoOnly(t *testing.T) {
	_, err := os.Open("/nonexistent/salary_review.xlsx")
	if got := errnoOnly(err).Error(); strings.Contains(got, "salary") {
		t.Errorf("path in error: %q", got)
	}
}
