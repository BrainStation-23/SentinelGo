package filedlp

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOpenSource(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cards.csv")
	if err := os.WriteFile(p, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		t.Fatal(err)
	}
	src := SourceRef{Path: p, Dev: st.Dev, Ino: st.Ino}
	f, ident, err := openSource(src)
	if err != nil || ident.Size != 4 || ident.Ino != st.Ino {
		t.Fatalf("open: %v %+v", err, ident)
	}
	_ = f.Close()
	// Replaced (a new file renamed over it, so a new inode): refused.
	tmp := filepath.Join(dir, "new")
	if err := os.WriteFile(tmp, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, p); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openSource(src); err == nil {
		t.Error("a replaced file was opened")
	}
	// A symlink is never followed.
	link := filepath.Join(dir, "link")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	_ = unix.Stat(p, &st)
	if _, _, err := openSource(SourceRef{Path: link, Dev: st.Dev, Ino: st.Ino}); err == nil {
		t.Error("followed a symlink")
	}
}

func TestProcStartTime(t *testing.T) {
	root := t.TempDir()
	procRoot = root
	t.Cleanup(func() { procRoot = "/proc" })
	mustWrite(t, filepath.Join(root, "stat"), "cpu  1 2 3\nbtime 1700000000\nprocesses 5\n")
	// A command name with spaces and a ")" must not shift the fields.
	fields := "S 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 12345 0"
	mustWrite(t, filepath.Join(root, "42", "stat"), "42 (my (weird) cmd) "+fields+"\n")
	want := time.Unix(1700000000, 0).Add(12345 * time.Second / 100)
	if got := procStartTime(42); !got.Equal(want) {
		t.Errorf("start %v, want %v", got, want)
	}
	if !procStartTime(43).IsZero() {
		t.Error("missing process")
	}
}

func TestRecordOpen(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(p, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	s := newTaintStore()
	recordOpen(s, fd, 7, "/elsewhere/")
	if s.len() != 0 {
		t.Error("recorded a file outside the root")
	}
	recordOpen(s, fd, 7, dir+"/")
	if got := s.sources(7, time.Time{}, time.Now(), time.Hour); len(got) != 1 || got[0].Path != p {
		t.Errorf("sources %v", got)
	}
}
