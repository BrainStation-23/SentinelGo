package walk

import (
	"io/fs"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/yara"
)

// fakeEntry is an os.DirEntry for fake listings.
type fakeEntry struct {
	name string
	dir  bool
}

func (e fakeEntry) Name() string { return e.name }
func (e fakeEntry) IsDir() bool  { return e.dir }
func (e fakeEntry) Type() fs.FileMode {
	if e.dir {
		return fs.ModeDir
	}
	return 0
}
func (e fakeEntry) Info() (fs.FileInfo, error) { return fakeInfo{e}, nil }

type fakeInfo struct{ e fakeEntry }

func (i fakeInfo) Name() string       { return i.e.name }
func (i fakeInfo) Size() int64        { return 1 }
func (i fakeInfo) Mode() fs.FileMode  { return i.e.Type() }
func (i fakeInfo) ModTime() time.Time { return time.Unix(1, 0) }
func (i fakeInfo) IsDir() bool        { return i.e.dir }
func (i fakeInfo) Sys() any           { return nil }

// fakeEnv is a device with the given folders (all existing) and variables.
func fakeEnv(goos string, homes []string, vars map[string]string, dirs ...string) Env {
	exists := map[string]bool{}
	children := map[string][]os.DirEntry{}
	sep := separator(goos)
	for _, d := range dirs {
		exists[strings.ToLower(d)] = true
		vol, rest := splitVolume(d, goos)
		parent := vol + sep
		for _, seg := range strings.Split(strings.Trim(rest, sep), sep) {
			child := join(parent, seg, sep)
			list := children[strings.ToLower(parent)]
			if !slices.ContainsFunc(list, func(e os.DirEntry) bool { return e.Name() == seg }) {
				children[strings.ToLower(parent)] = append(list, fakeEntry{name: seg, dir: true})
			}
			exists[strings.ToLower(child)] = true
			parent = child
		}
	}
	return Env{
		GOOS: goos, Homes: homes,
		Getenv: func(k string) string { return vars[k] },
		ReadDir: func(d string) ([]os.DirEntry, error) {
			l, ok := children[strings.ToLower(d)]
			if !ok {
				return nil, fs.ErrNotExist
			}
			return l, nil
		},
		FixedDrives: func() []string { return []string{`C:\`, `D:\`} },
		Exists:      func(p string) bool { return exists[strings.ToLower(p)] },
	}
}

func TestRoots_QuickWindows(t *testing.T) {
	env := fakeEnv("windows", []string{`C:\Users\a`, `C:\Users\b`},
		map[string]string{"PUBLIC": `C:\Users\Public`, "ProgramData": `C:\ProgramData`, "SystemRoot": `C:\Windows`},
		`C:\Users\a\Downloads`, `C:\Users\a\Desktop`, `C:\Users\a\AppData\Local\Temp`,
		`C:\Users\b\Downloads`, // b has no Desktop: dropped
		`C:\Users\Public`, `C:\ProgramData`, `C:\Windows\Temp`)
	got := Roots(yara.PresetQuick, nil, env)
	want := []string{`C:\Users\a\Downloads`, `C:\Users\a\Desktop`, `C:\Users\a\AppData\Local\Temp`,
		`C:\Users\b\Downloads`, `C:\Users\Public`, `C:\ProgramData`, `C:\Windows\Temp`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("quick roots\n%q\nwant\n%q", got, want)
	}
}

func TestRoots_QuickDarwinLinux(t *testing.T) {
	mac := fakeEnv("darwin", []string{"/Users/a"}, nil,
		"/Users/a/Downloads", "/Users/a/Library/LaunchAgents", "/private/tmp", "/private/var/folders", "/Library/LaunchDaemons")
	if got, want := Roots(yara.PresetQuick, nil, mac), []string{"/Users/a/Downloads", "/Users/a/Library/LaunchAgents",
		"/private/tmp", "/private/var/folders", "/Library/LaunchDaemons"}; !reflect.DeepEqual(got, want) {
		t.Errorf("darwin quick\n%q\nwant\n%q", got, want)
	}
	lin := fakeEnv("linux", []string{"/home/a", "/root"}, nil,
		"/home/a/Downloads", "/tmp", "/dev/shm", "/etc/cron.d", "/etc/cron.daily", "/etc/crontab.bak", "/root")
	got := Roots(yara.PresetQuick, nil, lin)
	want := []string{"/home/a/Downloads", "/tmp", "/dev/shm", "/etc/cron.d", "/etc/cron.daily", "/etc/crontab.bak", "/root"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("linux quick\n%q\nwant\n%q", got, want)
	}
}

func TestRoots_Full(t *testing.T) {
	win := fakeEnv("windows", nil, nil, `C:\`, `D:\`)
	if got := Roots(yara.PresetFull, nil, win); !reflect.DeepEqual(got, []string{`C:\`, `D:\`}) {
		t.Errorf("windows full = %q", got)
	}
	mac := fakeEnv("darwin", nil, nil, "/System/Volumes/Data")
	if got := Roots(yara.PresetFull, nil, mac); !reflect.DeepEqual(got, []string{"/System/Volumes/Data"}) {
		t.Errorf("darwin full = %q", got)
	}
	lin := fakeEnv("linux", nil, nil, "/")
	lin.Exists = func(string) bool { return true }
	if got := Roots(yara.PresetFull, nil, lin); !reflect.DeepEqual(got, []string{"/"}) {
		t.Errorf("linux full = %q", got)
	}
}

func TestRoots_PathsOverrideAndCustomEmpty(t *testing.T) {
	env := fakeEnv("linux", []string{"/home/a"}, nil, "/srv/app", "/srv/app/cache", "/opt/x")
	// Paths win over the preset; nested and duplicate roots merge.
	got := Roots(yara.PresetQuick, []string{"/srv/app/cache", "/srv/app", "/srv/app/", "/opt/x", "/missing"}, env)
	if !reflect.DeepEqual(got, []string{"/srv/app", "/opt/x"}) {
		t.Errorf("roots = %q", got)
	}
	if got := Roots(yara.PresetCustom, nil, env); got != nil {
		t.Errorf("custom with no paths = %q, want nothing on this OS", got)
	}
}

type expandCase struct {
	env  Env
	in   string
	want []string
}

func TestExpand(t *testing.T) {
	win := fakeEnv("windows", []string{`C:\Users\a`, `C:\Users\b`},
		map[string]string{"ProgramData": `C:\ProgramData`},
		`C:\Users\a\AppData\Roaming`, `C:\Users\b\AppData\Roaming`, `C:\Users\Public`)
	cases := []expandCase{
		{win, `%ProgramData%\x`, []string{`C:\ProgramData\x`}},
		{win, `%NOPE%\x`, nil}, // unset: nothing, never the working directory
		// Expand doesn't check existence (Roots does); literal segments keep their case.
		{win, `c:/users/*/appdata/roaming`, []string{`C:\users\Public\appdata\roaming`, `C:\users\a\appdata\roaming`, `C:\users\b\appdata\roaming`}},
		{win, `C:\Users\P*c`, []string{`C:\Users\Public`}},
		{win, `relative\path`, nil},
		{win, `C:\a\..\b`, []string{`C:\b`}},
		{win, `~\Downloads`, []string{`C:\Users\a\Downloads`, `C:\Users\b\Downloads`}},
	}
	lin := fakeEnv("linux", []string{"/home/a"}, map[string]string{"HOME": "/root", "X": "y"}, "/home/a/.config", "/home/b")
	cases = append(cases,
		expandCase{lin, "$HOME/.ssh", []string{"/root/.ssh"}},
		expandCase{lin, "/home/*/.config", []string{"/home/a/.config", "/home/b/.config"}},
		expandCase{lin, "/opt/${X}/[ab]?", []string{"/opt/y/[ab]?"}}, // only * is a wildcard
		expandCase{lin, "~/x", []string{"/home/a/x"}},
		expandCase{lin, "$UNSET/x", nil},
	)
	for _, tc := range cases {
		got := Expand(tc.in, tc.env)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("Expand(%q, %s) = %q, want %q", tc.in, tc.env.GOOS, got, tc.want)
		}
	}
}

func TestStarMatch(t *testing.T) {
	for _, tc := range []struct {
		pat, name  string
		fold, want bool
	}{
		{"*", "x", false, true},
		{"cron*", "cron.d", false, true},
		{"cron*", "anacrontab", false, false},
		{"*.d", "cron.d", false, true},
		{"a*b*c", "aXbYc", false, true},
		{"a*b*c", "abc", false, true},
		{"ab*ba", "aba", false, false}, // prefix and suffix may not overlap
		{"Users", "users", true, true},
		{"Users", "users", false, false},
	} {
		if got := starMatch(tc.pat, tc.name, tc.fold); got != tc.want {
			t.Errorf("starMatch(%q, %q) = %v, want %v", tc.pat, tc.name, got, tc.want)
		}
	}
}

func TestExcluder(t *testing.T) {
	win := fakeEnv("windows", nil, map[string]string{"ProgramData": `C:\ProgramData`})
	x := NewExcluder([]string{`D:\Builds`}, `C:\Program Files\Sentinel`, win)
	for path, want := range map[string]bool{
		`C:\sentinelgo\.sentinelgo\config.json`:                 true,
		`c:\programdata\microsoft\windows defender\scans\x.bin`: true,
		`C:\ProgramData\Other`:                                  false,
		`D:\builds\out.exe`:                                     true,
		`D:\Builds2\out.exe`:                                    false,
		`C:\Program Files\Sentinel\sentinelgo.exe`:              true,
		`E:\System Volume Information`:                          true,
		`C:\pagefile.sys`:                                       true,
		`C:\Users\a\Downloads\x.exe`:                            false,
	} {
		if got := x.Excluded(path, baseName(path, "windows")); got != want {
			t.Errorf("windows Excluded(%q) = %v, want %v", path, got, want)
		}
	}
	lin := NewExcluder([]string{"/dev/shm/cache", "/home/*/.cache"}, "", fakeEnv("linux", nil, nil, "/home/a/.cache"))
	for path, want := range map[string]bool{
		"/proc/1/maps":       true,
		"/dev":               false, // walked into, for /dev/shm
		"/dev/sda":           true,
		"/dev/shm/payload":   false,
		"/dev/shm/cache/x":   true, // the bundle's exclusion still applies
		"/opt/sentinelgo/a":  true,
		"/home/a/.cache/x":   true,
		"/home/a/Downloads":  false,
		"/sysroot/not-sys/x": false,
	} {
		if got := lin.Excluded(path, baseName(path, "linux")); got != want {
			t.Errorf("linux Excluded(%q) = %v, want %v", path, got, want)
		}
	}
	mac := NewExcluder([]string{"/Users/a/VMs"}, "", fakeEnv("darwin", nil, nil))
	for path, want := range map[string]bool{
		"/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara": true,
		// A full scan walks the data volume; firmlinked paths still match.
		"/System/Volumes/Data/Library/Apple/System/Library/CoreServices/XProtect.bundle/x": true,
		"/System/Volumes/Data/opt/sentinelgo/sentinelgo":                                   true,
		"/System/Volumes/Data/Users/a/VMs/disk.img":                                        true,
		"/System/Volumes/Data/Users/a/Downloads/x":                                         false,
		"/System/Volumes/Datax/opt/sentinelgo":                                             false,
	} {
		if got := mac.Excluded(path, baseName(path, "darwin")); got != want {
			t.Errorf("darwin Excluded(%q) = %v, want %v", path, got, want)
		}
	}
	var none *Excluder
	if none.Excluded("/x", "x") {
		t.Error("nil Excluder excluded a path")
	}
}
