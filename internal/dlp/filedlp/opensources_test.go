package filedlp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFdReadable(t *testing.T) {
	for in, want := range map[string]bool{
		"pos:\t0\nflags:\t0100000\nmnt_id:\t30": true,  // O_RDONLY|O_LARGEFILE
		"flags:\t02":                            true,  // O_RDWR
		"flags:\t0100001":                       false, // O_WRONLY
		"flags:\t0101101":                       false,
		"pos: 0":                                false,
		"flags: x":                              false,
	} {
		if fdReadable(in) != want {
			t.Errorf("%q: %v", in, !want)
		}
	}
}

func TestCandidatePath(t *testing.T) {
	for p, want := range map[string]bool{
		"/home/alice/report.xlsx":        true,
		"/srv/share/x.csv":               true,
		"/usr/share/fonts/a.ttf":         false,
		"/proc/1/maps":                   false,
		"socket:[1234]":                  false,
		"anon_inode:[eventfd]":           false,
		"/home/alice/gone.txt (deleted)": false,
		"/opt/sentinelgo/sentinelgo":     false,
	} {
		if candidatePath(p) != want {
			t.Errorf("%q: %v", p, !want)
		}
	}
}

// A fake /proc/<pid>: fd links and fdinfo. Symlinks need privileges on
// Windows, so the test runs where it can create them.
func TestOpenFileSources(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "42")
	for _, d := range []string{"fd", "fdinfo"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := func(fd, target, flags string) {
		if err := os.Symlink(target, filepath.Join(dir, "fd", fd)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "fdinfo", fd), []byte("pos:\t0\nflags:\t"+flags+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link("0", "/dev/pts/0", "02")
	link("3", "/home/alice/old.csv", "0100000")
	link("4", "/usr/share/fonts/a.ttf", "0100000")
	link("5", "/home/alice/secret.xlsx", "0100000")
	link("6", "/media/alice/USB/secret.xlsx", "0100101") // the destination
	link("7", "/home/alice/out.log", "0100001")          // write-only
	link("8", "socket:[99]", "02")
	link("9", "/home/alice/empty.txt", "0100000")
	link("10", "/home/alice/secret.xlsx", "0100000") // same file again
	stat := func(p string) (uint64, uint64, int64, bool) {
		switch p {
		case "/home/alice/old.csv":
			return 1, 10, 100, true
		case "/home/alice/secret.xlsx":
			return 1, 11, 5000, true
		case "/home/alice/empty.txt":
			return 1, 12, 0, true
		}
		return 0, 0, 0, false
	}
	isDest := func(p string) bool { return strings.HasPrefix(p, "/media/alice/USB/") }
	got := openFileSources(root, 42, isDest, stat, maxOpenSources)
	var paths []string
	for _, s := range got {
		paths = append(paths, s.Path)
	}
	if strings.Join(paths, ",") != "/home/alice/secret.xlsx,/home/alice/old.csv" {
		t.Fatalf("sources = %v", paths)
	}
	if got := openFileSources(root, 42, isDest, stat, 1); len(got) != 1 {
		t.Fatalf("limit: %v", got)
	}
	if got := openFileSources(root, 99, isDest, stat, 8); got != nil {
		t.Fatalf("missing pid: %v", got)
	}
}

// Only copy programs are judged at open time; an editor keeps unrelated
// documents open.
func TestIsCopyProgram(t *testing.T) {
	for p, want := range map[Process]bool{
		{Exe: "/usr/bin/cp"}:                  true,
		{Exe: "/usr/bin/nautilus"}:            true,
		{Exe: "/usr/libexec/kf6/kioworker"}:   true,
		{Name: "rsync"}:                       true,
		{Exe: "/usr/lib/libreoffice/soffice"}: false,
		{Exe: "/usr/bin/vim"}:                 false,
		{Exe: "/usr/bin/cp-evil", Name: "cp"}: false, // the exe decides when known
	} {
		if isCopyProgram(p) != want {
			t.Errorf("%+v: %v", p, !want)
		}
	}
}
