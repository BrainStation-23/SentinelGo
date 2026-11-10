package desktopproxy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeDesktop keeps gsettings and kioslaverc values in maps and answers the
// tools' command lines like the real ones.
type fakeDesktop struct {
	gnome map[string]string // gsettings key -> value ("" = default)
	kde   map[string]string // kioslaverc key -> value (missing = unset)
	tools map[string]bool
	calls []string
	fail  string // a command prefix that fails
}

func newFake() *fakeDesktop {
	return &fakeDesktop{
		gnome: map[string]string{gnomeMode: "none", gnomeAutoURL: ""},
		kde:   map[string]string{},
		tools: map[string]bool{"gsettings": true},
	}
}

func (f *fakeDesktop) run(name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, line)
	if f.fail != "" && strings.HasPrefix(line, f.fail) {
		return nil, errors.New("failed")
	}
	switch {
	case name == "gsettings" && args[0] == "get":
		return []byte(gvariantQuote(f.gnome[args[2]]) + "\n"), nil
	case name == "gsettings" && args[0] == "set":
		f.gnome[args[2]] = gvariantString(args[3])
	case name == "gsettings" && args[0] == "reset":
		f.gnome[args[2]] = map[string]string{gnomeMode: "none", gnomeAutoURL: ""}[args[2]]
	case strings.HasPrefix(name, "kreadconfig"):
		return []byte(f.kde[args[5]] + "\n"), nil
	case strings.HasPrefix(name, "kwriteconfig"):
		if args[6] == "--delete" {
			delete(f.kde, args[5])
		} else {
			f.kde[args[5]] = args[6]
		}
	}
	return nil, nil
}

func (f *fakeDesktop) manager(t *testing.T, desktop string) *Manager {
	t.Helper()
	return NewManager(Options{Run: f.run, Has: func(n string) bool { return f.tools[n] }, Desktop: desktop,
		NotePath: filepath.Join(t.TempDir(), "state", noteFile)})
}

const (
	noteFile = "upload-proxy.json"
	pac      = "http://127.0.0.1:3129/proxy.pac"
)

func TestGNOMESetAndRestore(t *testing.T) {
	f := newFake()
	m := f.manager(t, "ubuntu:GNOME")
	if err := m.Set(pac); err != nil {
		t.Fatal(err)
	}
	if f.gnome[gnomeMode] != "auto" || f.gnome[gnomeAutoURL] != pac {
		t.Fatalf("not set: %v", f.gnome)
	}
	if _, err := os.Stat(m.o.NotePath); err != nil {
		t.Fatalf("no note: %v", err)
	}
	f.calls = nil
	if err := m.Set(pac); err != nil { // already ours: only reads
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if !strings.HasPrefix(c, "gsettings get") {
			t.Errorf("unexpected %q", c)
		}
	}
	if err := m.Set(""); err != nil {
		t.Fatal(err)
	}
	if f.gnome[gnomeMode] != "none" || f.gnome[gnomeAutoURL] != "" {
		t.Errorf("not restored: %v", f.gnome)
	}
	if _, err := os.Stat(m.o.NotePath); !os.IsNotExist(err) {
		t.Errorf("note left: %v", err)
	}
	if err := m.Clear(); err != nil { // nothing to do
		t.Fatal(err)
	}
}

func TestRestoresExactPreviousValues(t *testing.T) {
	f := newFake()
	f.gnome[gnomeAutoURL] = "http://old.example/proxy.pac" // set, but mode none
	m := f.manager(t, "GNOME")
	if err := m.Set(pac); err != nil {
		t.Fatal(err)
	}
	if err := m.Clear(); err != nil {
		t.Fatal(err)
	}
	if f.gnome[gnomeMode] != "none" || f.gnome[gnomeAutoURL] != "http://old.example/proxy.pac" {
		t.Errorf("restored %v", f.gnome)
	}
}

func TestExistingProxyStandsDown(t *testing.T) {
	for _, mode := range []string{"manual", "auto"} {
		f := newFake()
		f.gnome[gnomeMode] = mode
		f.gnome[gnomeAutoURL] = "http://corp.example/wpad.dat"
		m := f.manager(t, "GNOME")
		if err := m.Set(pac); !errors.Is(err, ErrExistingProxy) || Reason(err) != "existing_proxy" {
			t.Fatalf("%s: %v", mode, err)
		}
		for _, c := range f.calls {
			if !strings.HasPrefix(c, "gsettings get") {
				t.Errorf("%s: changed something: %q", mode, c)
			}
		}
		if _, err := os.Stat(m.o.NotePath); !os.IsNotExist(err) {
			t.Errorf("%s: note written", mode)
		}
	}
}

func TestUserChangeAfterApply(t *testing.T) {
	f := newFake()
	m := f.manager(t, "GNOME")
	if err := m.Set(pac); err != nil {
		t.Fatal(err)
	}
	// The user turns the proxy off: the next Set puts it back.
	f.gnome[gnomeMode] = "none"
	if err := m.Set(pac); err != nil || f.gnome[gnomeMode] != "auto" {
		t.Fatalf("not reapplied: %v %v", err, f.gnome)
	}
	// The user sets a proxy of their own: stand down, keep theirs, drop the note.
	f.gnome[gnomeMode] = "manual"
	if err := m.Set(pac); !errors.Is(err, ErrExistingProxy) {
		t.Fatalf("got %v", err)
	}
	if f.gnome[gnomeMode] != "manual" {
		t.Errorf("theirs overwritten: %v", f.gnome)
	}
	if _, err := os.Stat(m.o.NotePath); !os.IsNotExist(err) {
		t.Errorf("note kept: %v", err)
	}
}

func TestClearLeavesTheirChanges(t *testing.T) {
	f := newFake()
	m := f.manager(t, "GNOME")
	if err := m.Set(pac); err != nil {
		t.Fatal(err)
	}
	f.gnome[gnomeAutoURL] = "http://theirs.example/p.pac"
	if err := m.Clear(); err != nil {
		t.Fatal(err)
	}
	if f.gnome[gnomeMode] != "auto" || f.gnome[gnomeAutoURL] != "http://theirs.example/p.pac" {
		t.Errorf("theirs changed: %v", f.gnome)
	}
}

func TestCrashRecoveryFromNote(t *testing.T) {
	f := newFake()
	m := f.manager(t, "GNOME")
	if err := m.Set(pac); err != nil {
		t.Fatal(err)
	}
	// A new helper (after kill -9) restores from the note on start.
	m2 := NewManager(m.o)
	if err := m2.Clear(); err != nil {
		t.Fatal(err)
	}
	if f.gnome[gnomeMode] != "none" {
		t.Errorf("not restored: %v", f.gnome)
	}
}

func TestNewPACURLKeepsOriginalPrevious(t *testing.T) {
	f := newFake()
	f.gnome[gnomeAutoURL] = "http://old.example/p.pac"
	m := f.manager(t, "GNOME")
	if err := m.Set(pac); err != nil {
		t.Fatal(err)
	}
	other := "http://127.0.0.1:40000/proxy.pac" // the proxy moved port
	if err := m.Set(other); err != nil || f.gnome[gnomeAutoURL] != other {
		t.Fatalf("%v %v", err, f.gnome)
	}
	if err := m.Clear(); err != nil {
		t.Fatal(err)
	}
	if f.gnome[gnomeMode] != "none" || f.gnome[gnomeAutoURL] != "http://old.example/p.pac" {
		t.Errorf("restored %v", f.gnome)
	}
}

func TestOursWithoutNoteRestoresDefaults(t *testing.T) {
	f := newFake()
	f.gnome[gnomeMode], f.gnome[gnomeAutoURL] = "auto", pac
	m := f.manager(t, "GNOME")
	if err := m.Set(pac); err != nil {
		t.Fatal(err)
	}
	if err := m.Clear(); err != nil {
		t.Fatal(err)
	}
	if f.gnome[gnomeMode] != "none" || f.gnome[gnomeAutoURL] != "" {
		t.Errorf("restored %v", f.gnome)
	}
}

func TestKDE(t *testing.T) {
	f := newFake()
	f.tools = map[string]bool{"kreadconfig6": true, "kwriteconfig6": true, "kreadconfig5": true, "kwriteconfig5": true, "dbus-send": true}
	m := f.manager(t, "KDE")
	m.o.KDESession = "6"
	if err := m.Set(pac); err != nil {
		t.Fatal(err)
	}
	if f.kde[kdeType] != "2" || f.kde[kdeScript] != pac {
		t.Fatalf("not set: %v", f.kde)
	}
	var used6, reparsed bool
	for _, c := range f.calls {
		used6 = used6 || strings.HasPrefix(c, "kwriteconfig6")
		reparsed = reparsed || strings.HasPrefix(c, "dbus-send")
		if strings.HasPrefix(c, "kwriteconfig5") {
			t.Errorf("Plasma 6 session used %q", c)
		}
	}
	if !used6 || !reparsed {
		t.Errorf("calls %v", f.calls)
	}
	if err := m.Clear(); err != nil {
		t.Fatal(err)
	}
	if len(f.kde) != 0 {
		t.Errorf("keys left: %v", f.kde)
	}
}

func TestKDEExistingAndAlsoGNOME(t *testing.T) {
	f := newFake()
	f.tools = map[string]bool{"kreadconfig5": true, "kwriteconfig5": true, "gsettings": true}
	f.kde[kdeType] = "1"
	m := f.manager(t, "KDE")
	if err := m.Set(pac); !errors.Is(err, ErrExistingProxy) {
		t.Fatalf("got %v", err)
	}
	if f.gnome[gnomeMode] != "none" {
		t.Errorf("GSettings changed: %v", f.gnome)
	}
	delete(f.kde, kdeType)
	if err := m.Set(pac); err != nil {
		t.Fatal(err)
	}
	if f.kde[kdeType] != "2" || f.gnome[gnomeMode] != "auto" { // both stores on Plasma
		t.Errorf("kde %v gnome %v", f.kde, f.gnome)
	}
	if err := m.Clear(); err != nil {
		t.Fatal(err)
	}
	if len(f.kde) != 0 || f.gnome[gnomeMode] != "none" {
		t.Errorf("kde %v gnome %v", f.kde, f.gnome)
	}
}

func TestUnsupportedDesktop(t *testing.T) {
	f := newFake()
	f.tools = map[string]bool{}
	m := f.manager(t, "XFCE")
	if err := m.Set(pac); !errors.Is(err, ErrUnsupportedDesktop) || Reason(err) != "unsupported_desktop" {
		t.Fatalf("got %v", err)
	}
	// gsettings without the proxy schema.
	f.tools["gsettings"] = true
	f.fail = "gsettings get"
	if err := m.Set(pac); !errors.Is(err, ErrUnsupportedDesktop) {
		t.Fatalf("got %v", err)
	}
}

func TestFailedSetRollsBack(t *testing.T) {
	f := newFake()
	f.fail = "gsettings set org.gnome.system.proxy mode 'auto'"
	m := f.manager(t, "GNOME")
	if err := m.Set(pac); err == nil || Reason(err) != "error" {
		t.Fatalf("got %v", err)
	}
	if f.gnome[gnomeAutoURL] != "" {
		t.Errorf("not rolled back: %v", f.gnome)
	}
	if _, err := os.Stat(m.o.NotePath); !os.IsNotExist(err) {
		t.Errorf("note left: %v", err)
	}
}

func TestGVariantRoundTrip(t *testing.T) {
	for _, s := range []string{"", "auto", `it's \ odd`, pac} {
		if got := gvariantString(gvariantQuote(s)); got != s {
			t.Errorf("%q -> %q", s, got)
		}
	}
	if got := gvariantString(`"it's"`); got != "it's" {
		t.Errorf("double quoted: %q", got)
	}
}
