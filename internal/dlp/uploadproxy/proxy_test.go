package uploadproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/filedlp"
	"sentinelgo/internal/dlp/filescan"
	"sentinelgo/internal/dlp/policy"
)

type recordingSink struct {
	mu  sync.Mutex
	evs []events.Event
}

func (r *recordingSink) Emit(ev events.Event) { r.mu.Lock(); r.evs = append(r.evs, ev); r.mu.Unlock() }

func (r *recordingSink) events() []events.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]events.Event(nil), r.evs...)
}

// inProcess scans in the test process; the service uses the sandboxed pool.
type inProcess struct{ s *filescan.Scanner }

func (p inProcess) Scan(ctx context.Context, f *os.File, size int64, _ time.Duration) filescan.Result {
	return p.s.Scan(ctx, filescan.Source{Size: size}, f)
}

func bundle(auditOnly bool, onUnscannable string) string {
	return bundleMax(auditOnly, onUnscannable, 0)
}

func bundleMax(auditOnly bool, onUnscannable string, maxFileBytes int64) string {
	return fmt.Sprintf(`{"schema_version": 1, "version": "v1", "enabled": true, "evidence_mode": "masked",
	  "modules": {"files": {"enabled": true, "channels": {"file.upload": true}, "audit_only": %v, "on_unscannable": %q, "max_file_bytes": %d,
	    "block_message": "Blocked: {{detector}}"}},
	  "policies": [{"id": "p1", "name": "Secrets", "severity": "high", "channels": ["file.upload"], "action": "block",
	    "detectors": [{"id": "custom.keywords", "rule_id": "kw", "min_count": 1, "keywords": ["TOPSECRET"]}]}]}`, auditOnly, onUnscannable, maxFileBytes)
}

// upstream is the "upload site": it records what reached it.
type upstream struct {
	srv   *httptest.Server
	mu    sync.Mutex
	got   [][]byte
	proto []string
}

func newUpstream(t *testing.T, tlsOn bool) *upstream {
	t.Helper()
	u := &upstream{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.got, u.proto = append(u.got, b), append(u.proto, r.Proto)
		u.mu.Unlock()
		_, _ = io.WriteString(w, "stored")
	})
	if tlsOn {
		u.srv = httptest.NewUnstartedServer(h)
		u.srv.EnableHTTP2 = true
		u.srv.StartTLS()
	} else {
		u.srv = httptest.NewServer(h)
	}
	t.Cleanup(u.srv.Close)
	return u
}

func (u *upstream) received() [][]byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([][]byte(nil), u.got...)
}

type fixture struct {
	ca      *CA
	proxy   *Proxy
	sink    *recordingSink
	client  *http.Client
	proxyAt string
	spill   string
}

// newFixture runs a proxy that intercepts everything on 127.0.0.1 and trusts
// up for upstream; the client trusts both the device CA and up's certificate.
func newFixture(t *testing.T, up *upstream, bundleJSON string, upstreamRoots *x509.CertPool) *fixture {
	t.Helper()
	dir, spill := t.TempDir(), t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := policy.Decode([]byte(bundleJSON))
	if err != nil {
		t.Fatal(err)
	}
	c := policy.Compile(b)
	eng, _ := c.FilesEngine()
	sink := &recordingSink{}
	d := filedlp.NewDecider(inProcess{filescan.New(eng, filescan.LimitsFrom(b.Modules.Files), spill)}, sink)
	d.Apply(c)
	if upstreamRoots == nil && up != nil && up.srv.TLS != nil {
		upstreamRoots = x509.NewCertPool()
		upstreamRoots.AddCert(up.srv.Certificate())
	}
	p := New(Options{
		CA:            ca,
		InScope:       func(host, _ string) bool { return host == "127.0.0.1" },
		Inspector:     NewInspector(d, spill),
		UpstreamRoots: upstreamRoots,
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() { _ = p.Serve(l) }()

	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate())
	if up != nil && up.srv.TLS != nil {
		roots.AddCert(up.srv.Certificate())
	}
	proxyURL := &url.URL{Scheme: "http", Host: l.Addr().String()}
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		TLSClientConfig:   &tls.Config{RootCAs: roots},
		ForceAttemptHTTP2: true,
	}}
	return &fixture{ca: ca, proxy: p, sink: sink, client: client, proxyAt: l.Addr().String(), spill: spill}
}

func multipartBody(t *testing.T, files map[string]string, fields map[string]string) (*bytes.Buffer, string) {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	for k, v := range fields {
		_ = w.WriteField(k, v)
	}
	for name, content := range files {
		fw, err := w.CreateFormFile("file", name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(fw, content)
	}
	_ = w.Close()
	return &b, w.FormDataContentType()
}

func post(t *testing.T, f *fixture, target string, body io.Reader, contentType string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func noSpillLeft(t *testing.T, dir string) {
	t.Helper()
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Errorf("spill files left: %v", left)
	}
}

// A file with sensitive data uploaded over HTTPS is refused; the site never
// sees the request; the event names the host and the file.
func TestProxy_BlocksSensitiveUpload(t *testing.T) {
	up := newUpstream(t, true)
	f := newFixture(t, up, bundle(false, "allow"), nil)
	body, ct := multipartBody(t, map[string]string{"q3.txt": "numbers TOPSECRET numbers"}, map[string]string{"note": "hi"})
	resp, text := post(t, f, up.srv.URL+"/upload", body, ct)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(text, "Blocked: custom.keywords") || strings.Contains(text, "TOPSECRET") {
		t.Fatalf("status %d body %q", resp.StatusCode, text)
	}
	if resp.ProtoMajor != 2 {
		t.Errorf("client to proxy spoke %s, want HTTP/2", resp.Proto)
	}
	if got := up.received(); len(got) != 0 {
		t.Errorf("the site received %d requests", len(got))
	}
	evs := f.sink.events()
	if len(evs) != 1 {
		t.Fatalf("events %+v", evs)
	}
	ev := evs[0]
	if ev.Action != events.ActionBlocked || ev.Channel != policy.ChannelFileUpload || ev.Destination.Type != "upload" ||
		ev.Destination.Host != "127.0.0.1" || ev.File.Name == nil || *ev.File.Name != "q3.txt" {
		t.Errorf("event %+v dest %+v file %+v", ev, ev.Destination, ev.File)
	}
	if st := f.proxy.Stats(); st.Intercepted != 1 || st.Blocked != 1 || st.Inspected != 1 {
		t.Errorf("stats %+v", st)
	}
	noSpillLeft(t, f.spill)
}

// Audit-only records but forwards, byte for byte; a clean upload passes
// without an event.
func TestProxy_AuditOnlyAndClean(t *testing.T) {
	up := newUpstream(t, true)
	f := newFixture(t, up, bundle(true, "allow"), nil)
	body, ct := multipartBody(t, map[string]string{"a.txt": "TOPSECRET"}, nil)
	want := body.String()
	resp, text := post(t, f, up.srv.URL+"/upload", body, ct)
	if resp.StatusCode != http.StatusOK || text != "stored" {
		t.Fatalf("status %d %q", resp.StatusCode, text)
	}
	if got := up.received(); len(got) != 1 || string(got[0]) != want {
		t.Errorf("the site got a different body")
	}
	if up.proto[0] != "HTTP/2.0" {
		t.Errorf("proxy to site spoke %s, want HTTP/2", up.proto[0])
	}
	evs := f.sink.events()
	if len(evs) != 1 || evs[0].Action != events.ActionMonitored {
		t.Errorf("events %+v", evs)
	}
	// Clean: forwarded, no event.
	resp, _ = post(t, f, up.srv.URL+"/upload", strings.NewReader(`{"text": "hello"}`), "application/json")
	if resp.StatusCode != http.StatusOK || len(f.sink.events()) != 1 {
		t.Errorf("clean upload: status %d, %d events", resp.StatusCode, len(f.sink.events()))
	}
	noSpillLeft(t, f.spill)
}

// A raw (non-multipart) body is inspected as a whole; plain HTTP too.
func TestProxy_RawBodyAndPlainHTTP(t *testing.T) {
	up := newUpstream(t, true)
	f := newFixture(t, up, bundle(false, "allow"), nil)
	if resp, _ := post(t, f, up.srv.URL+"/api", strings.NewReader(`{"doc": "TOPSECRET"}`), "application/json"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("raw body: %d", resp.StatusCode)
	}
	plain := newUpstream(t, false)
	if resp, _ := post(t, f, plain.srv.URL+"/api", strings.NewReader("TOPSECRET"), "text/plain"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("plain HTTP: %d", resp.StatusCode)
	}
	if len(plain.received()) != 0 {
		t.Error("plain HTTP upload reached the site")
	}
}

// A body over max_file_bytes is decided as too large (allowed by default)
// and forwarded in full, the rest streaming past the inspected part.
func TestProxy_OversizedBody(t *testing.T) {
	up := newUpstream(t, true)
	f := newFixture(t, up, bundleMax(false, "allow", 100), nil)
	payload := "TOPSECRET" + strings.Repeat("x", 5000)
	resp, _ := post(t, f, up.srv.URL+"/big", strings.NewReader(payload), "application/octet-stream")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := up.received(); len(got) != 1 || string(got[0]) != payload {
		t.Errorf("the site got %d bytes, want %d", len(got[0]), len(payload))
	}
	// With on_unscannable block it's refused instead.
	f = newFixture(t, up, bundleMax(false, "block", 100), nil)
	if resp, _ := post(t, f, up.srv.URL+"/big", strings.NewReader(payload), "application/octet-stream"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("on_unscannable block: %d", resp.StatusCode)
	}
}

// Hosts out of scope are tunnelled: the client talks TLS with the real site.
func TestProxy_TunnelsOutOfScope(t *testing.T) {
	up := newUpstream(t, true)
	f := newFixture(t, up, bundle(false, "allow"), nil)
	f.proxy.opts.InScope = func(string, string) bool { return false }
	body, ct := multipartBody(t, map[string]string{"a.txt": "TOPSECRET"}, nil)
	req, _ := http.NewRequest(http.MethodPost, up.srv.URL+"/upload", body)
	req.Header.Set("Content-Type", ct)
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !resp.TLS.PeerCertificates[0].Equal(up.srv.Certificate()) {
		t.Errorf("status %d, peer %s", resp.StatusCode, resp.TLS.PeerCertificates[0].Subject)
	}
	if len(f.sink.events()) != 0 || f.proxy.Stats().Tunnelled != 1 {
		t.Errorf("events %d stats %+v", len(f.sink.events()), f.proxy.Stats())
	}
}

// A site whose certificate isn't trusted gets nothing: the proxy never
// weakens TLS on the client's behalf.
func TestProxy_UntrustedUpstream(t *testing.T) {
	up := newUpstream(t, true)
	f := newFixture(t, up, bundle(false, "allow"), x509.NewCertPool()) // trusts nothing
	resp, _ := post(t, f, up.srv.URL+"/upload", strings.NewReader("hello"), "text/plain")
	if resp.StatusCode != http.StatusBadGateway || len(up.received()) != 0 {
		t.Errorf("status %d, site got %d", resp.StatusCode, len(up.received()))
	}
}

// A request on an intercepted connection can't be steered to another host.
func TestProxy_HostMismatch(t *testing.T) {
	up := newUpstream(t, true)
	f := newFixture(t, up, bundle(false, "allow"), nil)
	target := strings.TrimPrefix(up.srv.URL, "https://")
	conn, err := net.Dial("tcp", f.proxyAt)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(conn)
	if line, _ := br.ReadString('\n'); !strings.Contains(line, "200") {
		t.Fatalf("CONNECT: %q", line)
	}
	_, _ = br.ReadString('\n')
	roots := x509.NewCertPool()
	roots.AddCert(f.ca.Certificate())
	tc := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", NextProtos: []string{"http/1.1"}})
	_, _ = fmt.Fprintf(tc, "GET / HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d", resp.StatusCode)
	}
}

func TestHostScope(t *testing.T) {
	s := HostScope([]string{"drive.example.com", "*.uploads.example", " ", "API.Example.org"})
	for _, tc := range []struct {
		host, port string
		want       bool
	}{
		{"drive.example.com", "443", true},
		{"drive.example.com.", "443", true},
		{"api.example.org", "443", true},
		{"a.uploads.example", "443", true},
		{"uploads.example", "443", false},
		{"drive.example.com", "8443", false},
		{"drive.example.com", "80", true},
		{"example.com", "443", false},
	} {
		if got := s(tc.host, tc.port); got != tc.want {
			t.Errorf("%s:%s = %v", tc.host, tc.port, got)
		}
	}
}

func TestCA(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, CAKeyFile))
	if err != nil || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 { // Windows: an ACL (winsec)
		t.Errorf("key mode %v %v", fi.Mode(), err)
	}
	if c := ca.Certificate(); !c.IsCA || !c.MaxPathLenZero || c.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Errorf("CA cert %+v", c)
	}
	// Reloaded, not regenerated.
	again, err := LoadOrCreateCA(dir)
	if err != nil || again.Certificate().SerialNumber.Cmp(ca.Certificate().SerialNumber) != 0 {
		t.Errorf("reload: %v", err)
	}
	// Renewed when about to expire.
	later := func() time.Time { return time.Now().Add(caLifetime - caRenewAhead/2) }
	renewed, err := loadOrCreateCA(dir, later)
	if err != nil || renewed.Certificate().SerialNumber.Cmp(ca.Certificate().SerialNumber) == 0 {
		t.Errorf("not renewed: %v", err)
	}
	// Leaves verify for their host, are cached, and IPs get an IP SAN.
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate())
	for _, host := range []string{"drive.example.com", "10.1.2.3"} {
		leaf, err := ca.Leaf(host)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots}); err != nil {
			t.Errorf("%s: %v", host, err)
		}
		if leaf.Leaf.NotAfter.Sub(leaf.Leaf.NotBefore) > leafLifetime+2*time.Hour {
			t.Errorf("%s: lives %v", host, leaf.Leaf.NotAfter.Sub(leaf.Leaf.NotBefore))
		}
		if again, _ := ca.Leaf(host); again != leaf {
			t.Errorf("%s: not cached", host)
		}
	}
	// A corrupt CA file is an error, not silently replaced.
	if err := os.WriteFile(filepath.Join(dir, CACertFile), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(dir); err == nil {
		t.Error("a corrupt CA was accepted")
	}
}

// Upstream TLS verification is never skipped anywhere in this package.
func TestNoInsecureSkipVerify(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name) // #nosec G304 -- this package's own sources
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte("InsecureSkipVerify")) {
			t.Errorf("%s mentions InsecureSkipVerify", name)
		}
	}
}
