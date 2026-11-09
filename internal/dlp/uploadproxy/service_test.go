package uploadproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/dlp/filedlp"
	"sentinelgo/internal/dlp/filescan"
	"sentinelgo/internal/dlp/policy"
)

// fakeRedirector records what the service asked for.
type fakeRedirector struct {
	mu      sync.Mutex
	applied string
	calls   []string
	err     error
}

func (f *fakeRedirector) Apply(url string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	if f.applied != url {
		f.calls = append(f.calls, "apply")
	}
	f.applied = url
	return nil
}

func (f *fakeRedirector) Remove() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.applied != "" {
		f.calls = append(f.calls, "remove")
	}
	f.applied = ""
	return nil
}

func (f *fakeRedirector) state() (string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applied, strings.Join(f.calls, ",")
}

type fakeTruster struct {
	mu               sync.Mutex
	trusted, removed int
	err              error
}

func (f *fakeTruster) Trust(*CA) error { f.mu.Lock(); defer f.mu.Unlock(); f.trusted++; return f.err }
func (f *fakeTruster) Untrust() error  { f.mu.Lock(); defer f.mu.Unlock(); f.removed++; return nil }

func inspectionBundle(intercept string) string {
	return fmt.Sprintf(`{"schema_version": 1, "version": "v1", "enabled": true,
	  "modules": {"files": {"enabled": true, "channels": {"file.upload": true},
	    "uploads": {"inspection": {"enabled": true, "intercept": [%s], "bypass": ["login.example.com"]}}}},
	  "policies": [{"id": "p1", "name": "Secrets", "severity": "high", "channels": ["file.upload"], "action": "block",
	    "detectors": [{"id": "custom.keywords", "rule_id": "kw", "min_count": 1, "keywords": ["TOPSECRET"]}]}]}`, intercept)
}

func compileBundle(t *testing.T, raw string) *policy.Compiled {
	t.Helper()
	b, err := policy.Decode([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return policy.Compile(b)
}

func newTestService(t *testing.T, r *fakeRedirector, tr *fakeTruster) (*Service, string) {
	t.Helper()
	prev := watchdogEvery
	watchdogEvery = 50 * time.Millisecond
	t.Cleanup(func() { watchdogEvery = prev })
	dir := t.TempDir()
	c := compileBundle(t, inspectionBundle(`"drive.example.com"`))
	eng, _ := c.FilesEngine()
	s := NewService(ServiceOptions{Sink: &recordingSink{}, ConfigDir: dir, Addr: "127.0.0.1:0", Redirector: r, Truster: tr,
		Scanner: inProcess{filescan.New(eng, filescan.LimitsFrom(c.Bundle.Modules.Files), t.TempDir())}})
	t.Cleanup(s.Stop)
	return s, dir
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestService_Lifecycle(t *testing.T) {
	r, tr := &fakeRedirector{}, &fakeTruster{}
	s, dir := newTestService(t, r, tr)
	if s.Status() != nil {
		t.Error("status before inspection ever started")
	}
	c := compileBundle(t, inspectionBundle(`"drive.example.com", "*.dropbox.com"`))
	s.Apply(context.Background(), c)
	eventually(t, "the redirect", func() bool { a, _ := r.state(); return a != "" })
	if got := s.Capability(); got != "supported" {
		t.Errorf("capability %s", got)
	}
	applied, _ := r.state()
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Get(applied)
	if err != nil {
		t.Fatal(err)
	}
	pac, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	for _, want := range []string{`host == "drive.example.com"`, `dnsDomainIs(host, ".dropbox.com")`, `host == "login.example.com") return "DIRECT"`, "; DIRECT"} {
		if !strings.Contains(string(pac), want) {
			t.Errorf("PAC lacks %q:\n%s", want, pac)
		}
	}
	st := s.Status()
	if st == nil || st.Redirect != RedirectActive || st.Proxy != ProxyHealthy || st.CA == nil || len(st.CA.FingerprintSHA256) != 64 || st.Addr == "" {
		t.Fatalf("status %+v", st)
	}
	if tr.trusted != 1 {
		t.Errorf("trusted %d times", tr.trusted)
	}

	// The emergency switch removes the redirect; deleting it brings it back.
	sw := filepath.Join(dir, filedlp.OffSwitchFile)
	if err := os.WriteFile(sw, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the switch", func() bool { a, _ := r.state(); return a == "" })
	if got := s.Capability(); got != "unsupported:disabled_locally" {
		t.Errorf("capability while off: %s", got)
	}
	if err := os.Remove(sw); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the redirect again", func() bool { a, _ := r.state(); return a != "" })

	// Stop (shutdown): redirect removed, CA kept.
	s.Stop()
	if a, _ := r.state(); a != "" || tr.removed != 0 {
		t.Errorf("after stop: redirect %q, CA removed %d", a, tr.removed)
	}
	if got := s.Capability(); got != "unsupported:not_running" {
		t.Errorf("capability after stop: %s", got)
	}
	// Turned off by the policy: the CA leaves the trust store.
	s.Apply(context.Background(), compileBundle(t, strings.Replace(inspectionBundle(`"drive.example.com"`), `"enabled": true, "intercept"`, `"enabled": false, "intercept"`, 1)))
	if tr.removed != 1 {
		t.Errorf("CA removed %d times", tr.removed)
	}
}

func TestService_ExistingProxyAndUntrusted(t *testing.T) {
	r := &fakeRedirector{err: fmt.Errorf("%w: a machine proxy is set", ErrExistingProxy)}
	tr := &fakeTruster{err: fmt.Errorf("%w: needs a profile", ErrNeedsMDM)}
	s, _ := newTestService(t, r, tr)
	s.Apply(context.Background(), compileBundle(t, inspectionBundle(`"drive.example.com"`)))
	// The CA is checked first: inspection can't work without it.
	if got := s.Capability(); got != "unsupported:ca_needs_mdm" {
		t.Errorf("capability %s", got)
	}
	tr.err = nil
	s.Stop()
	s.Apply(context.Background(), compileBundle(t, inspectionBundle(`"drive.example.com"`)))
	eventually(t, "the redirect attempt", func() bool { return s.Status().Redirect == "unsupported:existing_proxy" })
	if got := s.Capability(); got != "unsupported:existing_proxy" {
		t.Errorf("capability %s", got)
	}
	if a, _ := r.state(); a != "" {
		t.Errorf("redirected despite an existing proxy: %s", a)
	}
}

// A proxy that stops answering loses its redirect (fail open).
func TestService_WatchdogRemovesRedirectWhenDown(t *testing.T) {
	r, tr := &fakeRedirector{}, &fakeTruster{}
	s, _ := newTestService(t, r, tr)
	s.Apply(context.Background(), compileBundle(t, inspectionBundle(`"drive.example.com"`)))
	eventually(t, "the redirect", func() bool { a, _ := r.state(); return a != "" })
	s.mu.Lock()
	_ = s.ln.Close() // the proxy dies
	s.mu.Unlock()
	eventually(t, "the redirect removed", func() bool { a, _ := r.state(); return a == "" })
	if got := s.Capability(); got != "unsupported:proxy_down" {
		t.Errorf("capability %s", got)
	}
}

func TestWithUploads(t *testing.T) {
	r, tr := &fakeRedirector{}, &fakeTruster{}
	s, _ := newTestService(t, r, tr)
	e := WithUploads(nil, s)
	off := compileBundle(t, strings.Replace(inspectionBundle(`"drive.example.com"`), `"enabled": true, "intercept"`, `"enabled": false, "intercept"`, 1))
	if e.Wants(off.Modules.Files) {
		t.Error("wants without inspection")
	}
	e.Apply(context.Background(), off)
	if caps := e.Capabilities(); caps[policy.ChannelFileUpload] != "unsupported:inspection_off" {
		t.Errorf("caps %v", caps)
	}
	if e.Health() != nil || e.CopyCorrelation() != nil {
		t.Error("health before inspection")
	}
	on := compileBundle(t, inspectionBundle(`"drive.example.com"`))
	if !e.Wants(on.Modules.Files) {
		t.Error("doesn't want inspection")
	}
	e.Apply(context.Background(), on)
	eventually(t, "supported", func() bool { return e.Capabilities()[policy.ChannelFileUpload] == "supported" })
	h := e.Health()
	if h == nil || h.DeepInspection == nil {
		t.Fatalf("health %+v", h)
	}
	if _, ok := h.DeepInspection.(*Status); !ok {
		t.Errorf("deep_inspection %T", h.DeepInspection)
	}
	e.Stop()
}

func TestBuildPAC_SkipsUnsafe(t *testing.T) {
	pac := string(BuildPAC("127.0.0.1:3129", []string{`a.example.com`, `x"); evil(); ("`}, nil))
	if strings.Contains(pac, "evil") || !strings.Contains(pac, `"a.example.com"`) {
		t.Errorf("pac:\n%s", pac)
	}
	if Reason(errors.New("x")) != "error" || Reason(fmt.Errorf("w: %w", ErrNeedsMDM)) != "ca_needs_mdm" {
		t.Error("reasons")
	}
	if !Scope([]string{"*.example.com"}, []string{"login.example.com"})("drive.example.com", "443") ||
		Scope([]string{"*.example.com"}, []string{"login.example.com"})("login.example.com", "443") {
		t.Error("scope")
	}
}

func TestIsOurCA(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !isOurCA(ca.Certificate().Raw) || isOurCA([]byte("nope")) {
		t.Error("isOurCA")
	}
}
