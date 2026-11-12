package walk

import (
	"errors"
	"io/fs"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestOnWriteRoots_Defaults(t *testing.T) {
	win := fakeEnv("windows", []string{`C:\Users\a`},
		map[string]string{"PUBLIC": `C:\Users\Public`, "ProgramData": `C:\ProgramData`, "SystemRoot": `C:\Windows`},
		`C:\Users\a\Downloads`, `C:\Users\a\AppData\Local\Temp`, `C:\Users\Public`,
		`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`, `C:\Windows\Temp`)
	want := []string{`C:\Users\a\Downloads`, `C:\Users\a\AppData\Local\Temp`, `C:\Users\Public`,
		`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`, `C:\Windows\Temp`}
	if got := OnWriteRoots(nil, win); !reflect.DeepEqual(got, want) {
		t.Errorf("windows\n%q\nwant\n%q", got, want)
	}
	mac := fakeEnv("darwin", []string{"/Users/a"}, nil,
		"/Users/a/Downloads", "/private/tmp", "/private/var/folders", "/Library/LaunchDaemons")
	if got, want := OnWriteRoots(nil, mac), []string{"/Users/a/Downloads", "/private/tmp", "/Library/LaunchDaemons"}; !reflect.DeepEqual(got, want) {
		t.Errorf("darwin\n%q\nwant\n%q", got, want)
	}
	lin := fakeEnv("linux", []string{"/home/a", "/root"}, nil,
		"/home/a/Downloads", "/tmp", "/dev/shm", "/etc/cron.d", "/root")
	if got, want := OnWriteRoots(nil, lin), []string{"/home/a/Downloads", "/tmp", "/dev/shm", "/etc/cron.d"}; !reflect.DeepEqual(got, want) {
		t.Errorf("linux (no /root)\n%q\nwant\n%q", got, want)
	}
}

func TestOnWriteRoots_BundlePaths(t *testing.T) {
	lin := fakeEnv("linux", []string{"/home/a"}, nil, "/home/a/Downloads", "/srv/drop", "/srv/drop/in")
	if got, want := OnWriteRoots([]string{"/srv/drop", "/srv/drop/in", "/missing"}, lin), []string{"/srv/drop"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestUnder(t *testing.T) {
	roots := []string{`C:\Users\a\Downloads`, `C:\Windows\Temp`}
	if r, ok := Under(`c:\users\A\downloads\x\y.exe`, roots, "windows"); !ok || r != roots[0] {
		t.Errorf("Under = %q, %v", r, ok)
	}
	if _, ok := Under(`C:\Users\a\Downloads2\y.exe`, roots, "windows"); ok {
		t.Error("a sibling folder counted as inside")
	}
	if _, ok := Under("/tmp/X", []string{"/tmp/x"}, "linux"); ok {
		t.Error("linux compared case-insensitively")
	}
}

func TestStat(t *testing.T) {
	root := tree(t, map[string]string{"a.bin": "abc", "big.bin": "0123456789", "skip/x.bin": "x"})
	env := DefaultEnv()
	o := Options{GOOS: runtime.GOOS, MaxFileBytes: 5,
		Exclude: NewExcluder([]string{filepath.Join(root, "skip")}, "", env)}

	f, reason, err := Stat(o, filepath.Join(root, "a.bin"))
	if err != nil || reason != "" || f.Size != 3 || f.Key.Path != filepath.Join(root, "a.bin") {
		t.Fatalf("a.bin: %+v %q %v", f, reason, err)
	}
	fh, err := Open(f)
	if err != nil {
		t.Fatalf("Open after Stat: %v", err)
	}
	_ = fh.Close()

	for name, want := range map[string]string{"big.bin": SkipTooLarge, "skip/x.bin": SkipExcluded} {
		if _, reason, err := Stat(o, filepath.Join(root, filepath.FromSlash(name))); err != nil || reason != want {
			t.Errorf("%s: reason %q err %v, want %q", name, reason, err, want)
		}
	}
	if _, reason, err := Stat(o, root); err != nil || reason != SkipSpecial {
		t.Errorf("folder: reason %q err %v", reason, err)
	}
	if _, _, err := Stat(o, filepath.Join(root, "gone")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: err %v", err)
	}

	// The skip cache: same file, same rules → unchanged.
	c, err := OpenCache(filepath.Join(t.TempDir(), "c"), runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	c.Store(f.Key, "r@1", Clean)
	o.Cache, o.Rules = c, "r@1"
	if _, reason, _ := Stat(o, f.Path); reason != SkipUnchanged {
		t.Errorf("cached file: reason %q", reason)
	}
	o.Rules = "r@2"
	if _, reason, _ := Stat(o, f.Path); reason != "" {
		t.Errorf("new rules: reason %q", reason)
	}
}

func TestStat_Mounts(t *testing.T) {
	o := Options{GOOS: "linux", Mounts: []Mount{{Path: "/media/usb"}, {Path: "/mnt/share", Network: true}}}
	if r := excludedReason(o, "/media/usb/a/x"); r != SkipRemovable {
		t.Errorf("removable: %q", r)
	}
	if r := excludedReason(o, "/mnt/share/x"); r != SkipNetwork {
		t.Errorf("network: %q", r)
	}
	o.IncludeNetwork, o.IncludeRemovable = true, true
	if Excluded(o, "/media/usb/x") || Excluded(o, "/mnt/share/x") {
		t.Error("included mounts still excluded")
	}
	if !Excluded(Options{GOOS: "windows"}, `\\server\share\x.exe`) {
		t.Error("UNC path not skipped as a network share")
	}
}
