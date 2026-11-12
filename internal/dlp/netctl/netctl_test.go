package netctl

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/dlp/filedlp"
	"sentinelgo/internal/dlp/policy"
)

func TestExpandApp(t *testing.T) {
	env := map[string]string{"programfiles": `C:\Program Files`, "systemroot": `C:\Windows`}
	profiles := []string{`C:\Users\ana`, `C:\Users\bo`}
	for _, tc := range []struct {
		app    policy.App
		want   []string
		reason string
	}{
		{policy.App{Path: `%ProgramFiles%\WeTransfer\wt.exe`}, []string{`C:\Program Files\WeTransfer\wt.exe`}, ""},
		{policy.App{Path: `C:\Tools\x.exe`}, []string{`C:\Tools\x.exe`}, ""},
		{policy.App{Path: `\\srv\apps\x.exe`}, []string{`\\srv\apps\x.exe`}, ""},
		{policy.App{Path: `%LOCALAPPDATA%\Dropbox\Client\Dropbox.exe`},
			[]string{`C:\Users\ana\AppData\Local\Dropbox\Client\Dropbox.exe`, `C:\Users\bo\AppData\Local\Dropbox\Client\Dropbox.exe`}, ""},
		{policy.App{Path: `%AppData%\Tool\t.exe`}, []string{`C:\Users\ana\AppData\Roaming\Tool\t.exe`, `C:\Users\bo\AppData\Roaming\Tool\t.exe`}, ""},
		{policy.App{Path: `%USERPROFILE%\bin\t.exe`}, []string{`C:\Users\ana\bin\t.exe`, `C:\Users\bo\bin\t.exe`}, ""},
		{policy.App{Signer: "Dropbox, Inc."}, nil, ReasonSignerOnly},
		{policy.App{Path: `Dropbox.exe`}, nil, ReasonNotAbsolute},
		{policy.App{Path: `C:\Tools\*.exe`}, nil, ReasonNotAbsolute},
		{policy.App{Path: `%NOPE%\x.exe`}, nil, ReasonNotAbsolute},
		{policy.App{Path: `%ProgramFiles\x.exe`}, nil, ReasonNotAbsolute},
	} {
		got, reason := expandApp(tc.app, env, profiles)
		if !reflect.DeepEqual(got, tc.want) || reason != tc.reason {
			t.Errorf("%+v: %q %q, want %q %q", tc.app, got, reason, tc.want, tc.reason)
		}
	}
}

// fakeRules records what the controller applied.
type fakeRules struct {
	mu     sync.Mutex
	opens  int
	sets   int
	rules  Rules
	open   bool
	setErr error
}

func (f *fakeRules) Set(r Rules) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setErr != nil {
		return f.setErr
	}
	f.sets++
	f.rules = r
	return nil
}

func (f *fakeRules) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.open = false
	return nil
}

func (f *fakeRules) state() (bool, int, Rules) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.open, f.sets, f.rules
}

type fixture struct {
	ctl     *Controller
	rules   *fakeRules
	openErr error

	mu     sync.Mutex
	exists map[string]bool
}

func (f *fixture) install(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.exists[path] = true
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{rules: &fakeRules{}, exists: map[string]bool{
		`C:\Users\ana\AppData\Local\Dropbox\Client\Dropbox.exe`: true,
		`C:\Program Files\WeTransfer\wt.exe`:                    true,
	}}
	f.ctl = New(Options{
		GOOS: "windows",
		Open: func() (Ruleset, error) {
			if f.openErr != nil {
				return nil, f.openErr
			}
			f.rules.mu.Lock()
			f.rules.opens++
			f.rules.open = true
			f.rules.mu.Unlock()
			return f.rules, nil
		},
		Resolve: func(_ context.Context, host string) ([]netip.Addr, time.Duration, error) {
			if host == "files.example.com" {
				return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, time.Minute, nil
			}
			return nil, 0, errors.New("nxdomain")
		},
		Env:      func() map[string]string { return map[string]string{"programfiles": `C:\Program Files`} },
		Profiles: func() []string { return []string{`C:\Users\ana`, `C:\Users\bo`} },
		Exists: func(p string) bool {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.exists[p]
		},
	})
	t.Cleanup(f.ctl.Stop)
	return f
}

func bundle(t *testing.T, auditOnly bool, control string) *policy.Compiled {
	t.Helper()
	raw := fmt.Sprintf(`{"schema_version": 1, "version": "v1", "enabled": true, "evidence_mode": "masked",
	  "modules": {"files": {"enabled": true, "channels": {"file.removable": true}, "audit_only": %v %s}},
	  "policies": []}`, auditOnly, control)
	b, err := policy.Decode([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return policy.Compile(b)
}

const controls = `, "network_control": {"enabled": true,
  "blocked_apps": {"windows": [
    {"path": "%LOCALAPPDATA%\\Dropbox\\Client\\Dropbox.exe", "name": "Dropbox"},
    {"path": "%ProgramFiles%\\WeTransfer\\wt.exe"},
    {"path": "C:\\Missing\\m.exe", "name": "Missing"},
    {"signer": "Some Signer", "name": "Signed"}]},
  "allow_destinations": ["files.example.com", "*.corp.example.com", "10.0.0.0/8", "gone.example.com"]}`

func TestController_Enforces(t *testing.T) {
	f := newFixture(t)
	f.ctl.Apply(context.Background(), bundle(t, false, controls))
	open, sets, r := f.rules.state()
	if !open || sets != 1 {
		t.Fatalf("open %v sets %d", open, sets)
	}
	wantApps := []string{`C:\Program Files\WeTransfer\wt.exe`, `C:\Users\ana\AppData\Local\Dropbox\Client\Dropbox.exe`}
	if !reflect.DeepEqual(r.BlockApps, wantApps) {
		t.Errorf("apps %q", r.BlockApps)
	}
	wantAllow := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.0.2.10/32")}
	if !reflect.DeepEqual(r.Allow, wantAllow) {
		t.Errorf("allow %v", r.Allow)
	}
	st := f.ctl.Status()
	want := &Status{State: StateActive,
		BlockedApps:       AppsStatus{Applied: 2, NotApplied: []NotApplied{{"Missing", ReasonPathNotFound}, {"Signed", ReasonSignerOnly}}},
		AllowDestinations: AllowStatus{Addresses: 2, Unresolved: 1, Patterns: 1}}
	if !reflect.DeepEqual(st, want) {
		t.Errorf("status %+v", st)
	}
	if caps := f.ctl.Capabilities(); caps[CapBlockedApps] != "supported" || caps[CapTaintBlock] != "unsupported:not_implemented" {
		t.Errorf("caps %v", caps)
	}

	// The same policy again: nothing rewritten. An app installed since is
	// picked up on the next sync.
	f.ctl.Apply(context.Background(), bundle(t, false, controls))
	if _, sets, _ := f.rules.state(); sets != 1 {
		t.Errorf("unchanged rules rewritten: %d", sets)
	}
	f.install(`C:\Missing\m.exe`)
	f.ctl.sync(context.Background())
	if _, sets, r := f.rules.state(); sets != 2 || len(r.BlockApps) != 3 {
		t.Errorf("new app: sets %d apps %q", sets, r.BlockApps)
	}

	// The block off: rules removed, no status.
	f.ctl.Apply(context.Background(), bundle(t, false, ""))
	if open, _, _ := f.rules.state(); open || f.ctl.Status() != nil || f.ctl.Capabilities() != nil {
		t.Errorf("off: open %v status %+v", open, f.ctl.Status())
	}
}

// Audit-only says what would be blocked and never opens the firewall.
func TestController_AuditOnly(t *testing.T) {
	f := newFixture(t)
	f.ctl.Apply(context.Background(), bundle(t, true, controls))
	if f.rules.opens != 0 {
		t.Errorf("firewall opened in audit only")
	}
	if st := f.ctl.Status(); st.State != StateAuditOnly || st.BlockedApps.Applied != 2 {
		t.Errorf("status %+v", st)
	}
	// Leaving audit-only applies; going back removes.
	f.ctl.Apply(context.Background(), bundle(t, false, controls))
	if open, _, _ := f.rules.state(); !open {
		t.Error("not applied after audit-only")
	}
	f.ctl.Apply(context.Background(), bundle(t, true, controls))
	if open, _, _ := f.rules.state(); open || f.ctl.Status().State != StateAuditOnly {
		t.Errorf("back to audit only: open %v", open)
	}
}

func TestController_Failures(t *testing.T) {
	f := newFixture(t)
	f.openErr = errors.New("access denied")
	f.ctl.Apply(context.Background(), bundle(t, false, controls))
	if st := f.ctl.Status(); st.State != "unsupported:wfp_error" || f.ctl.Capabilities()[CapBlockedApps] != "unsupported:wfp_error" {
		t.Errorf("open failed: %+v %v", st, f.ctl.Capabilities())
	}
	f.openErr = nil
	f.rules.setErr = errors.New("bad filter")
	f.ctl.sync(context.Background())
	if open, _, _ := f.rules.state(); open || f.ctl.Status().State != "unsupported:wfp_error" {
		t.Errorf("set failed: open %v %+v", open, f.ctl.Status())
	}
	f.rules.setErr = nil
	f.ctl.sync(context.Background())
	if f.ctl.Status().State != StateActive || f.ctl.Capabilities()[CapBlockedApps] != "supported" {
		t.Errorf("recovered: %+v", f.ctl.Status())
	}
}

// Elsewhere the controls are reported, never applied.
func TestController_NotWindows(t *testing.T) {
	ctl := New(Options{GOOS: "linux", Open: func() (Ruleset, error) { t.Fatal("opened on linux"); return nil, nil }})
	c := bundle(t, false, controls)
	if ctl.Wants(c.Modules.Files) {
		t.Error("wants on linux")
	}
	ctl.Apply(context.Background(), c)
	if caps := ctl.Capabilities(); caps[CapBlockedApps] != "unsupported:not_on_windows" || caps[CapTaintBlock] != "unsupported:not_on_windows" {
		t.Errorf("caps %v", caps)
	}
	if st := ctl.Status(); st == nil || st.State != "unsupported:not_on_windows" {
		t.Errorf("status %+v", st)
	}
}

// The refresh loop re-resolves and picks up changes on its own.
func TestController_Refreshes(t *testing.T) {
	defer func(d time.Duration) { refreshEvery = d }(refreshEvery)
	refreshEvery = 10 * time.Millisecond
	f := newFixture(t)
	f.ctl.Apply(context.Background(), bundle(t, false, controls))
	f.install(`C:\Missing\m.exe`)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, r := f.rules.state(); len(r.BlockApps) == 3 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("refresh didn't pick up the new app")
}

// fakeFiles is a file DLP enforcer for the wrapper.
type fakeFiles struct{ applied int }

func (f *fakeFiles) Apply(context.Context, *policy.Compiled) { f.applied++ }
func (f *fakeFiles) Stop()                                   {}
func (f *fakeFiles) Wants(policy.FilesModule) bool           { return false }
func (f *fakeFiles) Capabilities() map[string]string {
	return map[string]string{"file.removable": "supported"}
}
func (f *fakeFiles) CopyCorrelation() map[string]string { return nil }
func (f *fakeFiles) Health() *filedlp.Health            { return &filedlp.Health{State: "running", Mounts: 2} }

func TestWith(t *testing.T) {
	f := newFixture(t)
	files := &fakeFiles{}
	e := With(files, f.ctl)
	c := bundle(t, false, controls)
	if !e.Wants(c.Modules.Files) {
		t.Error("wrapper doesn't want the controls")
	}
	e.Apply(context.Background(), c)
	caps := e.Capabilities()
	if files.applied != 1 || caps["file.removable"] != "supported" || caps[CapBlockedApps] != "supported" {
		t.Errorf("applied %d caps %v", files.applied, caps)
	}
	h := e.Health()
	if st, ok := h.NetworkControl.(*Status); !ok || h.Mounts != 2 || st.State != StateActive {
		t.Errorf("health %+v", h)
	}
	if _, ok := caps[CapTaintBlock]; !ok {
		t.Error("taint capability missing")
	}
	e.Stop()
	if open, _, _ := f.rules.state(); open {
		t.Error("Stop left the rules")
	}
}
