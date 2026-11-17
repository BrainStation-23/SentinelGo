package uploadproxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// waitUninspectable waits for the proxy to record want uploads for reason
// (the server side of a failed handshake finishes after the client gives up).
func waitUninspectable(t *testing.T, p *Proxy, reason string, want uint64) (map[string]uint64, []UninspectableHost) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		counts, hosts := p.Uninspectable()
		if counts[reason] >= want || time.Now().After(deadline) {
			return counts, hosts
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A client that doesn't trust the device CA (or pins the real certificate)
// refuses the proxy's certificate: counted as tls_untrusted for the host.
func TestUninspectable_ClientRejectsCA(t *testing.T) {
	up := newUpstream(t, true)
	f := newFixture(t, up, bundle(false, "allow"), nil)
	roots := x509.NewCertPool() // the real site's certificate only, not the device CA
	roots.AddCert(up.srv.Certificate())
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: f.proxyAt}),
		TLSClientConfig: &tls.Config{RootCAs: roots},
	}}
	if resp, err := client.Post(up.srv.URL+"/upload", "application/octet-stream", strings.NewReader("TOPSECRET")); err == nil {
		_ = resp.Body.Close()
		t.Fatal("a client without the device CA connected")
	}
	counts, hosts := waitUninspectable(t, f.proxy, ReasonTLSUntrusted, 1)
	if counts[ReasonTLSUntrusted] != 1 || len(hosts) != 1 || hosts[0].Host != "127.0.0.1" || hosts[0].Reason != ReasonTLSUntrusted {
		t.Fatalf("counts %v hosts %+v", counts, hosts)
	}
	if got := up.received(); len(got) != 0 {
		t.Errorf("the site got %d requests", len(got))
	}
}

// Something that isn't TLS after CONNECT never got a certificate: an error,
// but not an uninspectable upload.
func TestUninspectable_NotTLSIsNotCounted(t *testing.T) {
	up := newUpstream(t, true)
	f := newFixture(t, up, bundle(false, "allow"), nil)
	c, err := net.Dial("tcp", f.proxyAt)
	if err != nil {
		t.Fatal(err)
	}
	target := strings.TrimPrefix(up.srv.URL, "https://")
	_, _ = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	if line, _ := br.ReadString('\n'); !strings.Contains(line, "200") {
		t.Fatalf("CONNECT: %q", line)
	}
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\n\r\n")) // plain text, not a ClientHello
	_ = c.Close()
	deadline := time.Now().Add(3 * time.Second)
	for f.proxy.Stats().Errors == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if f.proxy.Stats().Errors == 0 {
		t.Fatal("the failed handshake wasn't counted as an error")
	}
	if counts, _ := f.proxy.Uninspectable(); counts != nil {
		t.Errorf("not-TLS counted as uninspectable: %v", counts)
	}
}

// A WebSocket upgrade to an intercepted host is relayed, but its stream isn't
// read: counted as websocket.
func TestUninspectable_WebSocket(t *testing.T) {
	up := newUpstream(t, true)
	f := newFixture(t, up, bundle(false, "allow"), nil)
	tr := f.client.Transport.(*http.Transport).Clone()
	tr.ForceAttemptHTTP2 = false
	tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{} // HTTP/1.1: upgrades need it
	client := &http.Client{Timeout: 10 * time.Second, Transport: tr}
	req, _ := http.NewRequest(http.MethodGet, up.srv.URL+"/socket", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	if resp, err := client.Do(req); err == nil {
		_ = resp.Body.Close()
	}
	counts, hosts := waitUninspectable(t, f.proxy, ReasonWebSocket, 1)
	if counts[ReasonWebSocket] != 1 || len(hosts) != 1 || hosts[0].Reason != ReasonWebSocket {
		t.Fatalf("counts %v hosts %+v", counts, hosts)
	}
	// An ordinary upload isn't.
	if resp, _ := post(t, f, up.srv.URL+"/upload", strings.NewReader("clean"), "application/octet-stream"); resp.StatusCode != http.StatusOK {
		t.Fatalf("upload status %d", resp.StatusCode)
	}
	if counts, _ := f.proxy.Uninspectable(); counts[ReasonWebSocket] != 1 || len(counts) != 1 {
		t.Errorf("counts after an upload: %v", counts)
	}
}

// A body over max_file_bytes is counted as too_large, and nothing the client
// sent (body, path, query) is in the status.
func TestUninspectable_TooLargeAndPrivacy(t *testing.T) {
	up := newUpstream(t, true)
	f := newFixture(t, up, bundleMax(false, "allow", 100), nil)
	payload := "TOPSECRET" + strings.Repeat("x", 5000)
	resp, _ := post(t, f, up.srv.URL+"/private-folder/report.pdf?token=QUERYSECRET", strings.NewReader(payload), "application/octet-stream")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	counts, hosts := f.proxy.Uninspectable()
	if counts[ReasonTooLarge] != 1 || len(hosts) != 1 || hosts[0].Reason != ReasonTooLarge || hosts[0].Host != "127.0.0.1" {
		t.Fatalf("counts %v hosts %+v", counts, hosts)
	}
	b, err := json.Marshal(Status{UninspectableCounts: counts, UninspectableHosts: hosts})
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"TOPSECRET", "private-folder", "report.pdf", "QUERYSECRET", "xxxx"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("status carries %q: %s", leak, b)
		}
	}
	// A body within the limit isn't counted.
	if resp, _ := post(t, f, up.srv.URL+"/small", strings.NewReader("small"), "application/octet-stream"); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if counts, _ := f.proxy.Uninspectable(); counts[ReasonTooLarge] != 1 {
		t.Errorf("counts %v", counts)
	}
}

// Repeats of a host and reason fold into one entry; the list keeps the 20
// most recent; host names are normalized and bounded.
func TestUninspectable_DedupeAndCap(t *testing.T) {
	now := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	u := newUninspectable(func() time.Time { return now })
	if c, h := u.snapshot(); c != nil || h != nil {
		t.Fatalf("empty: %v %v", c, h)
	}
	for i := 0; i < 3; i++ {
		u.add("Upload.Example.COM.", ReasonTLSUntrusted)
		now = now.Add(time.Minute)
	}
	u.add("upload.example.com", ReasonWebSocket)
	counts, hosts := u.snapshot()
	if counts[ReasonTLSUntrusted] != 3 || counts[ReasonWebSocket] != 1 || len(hosts) != 2 {
		t.Fatalf("counts %v hosts %+v", counts, hosts)
	}
	tls := hosts[1]
	if tls.Host != "upload.example.com" || tls.Count != 3 || !tls.FirstAt.Equal(time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)) ||
		!tls.LastAt.Equal(time.Date(2026, 11, 17, 9, 2, 0, 0, time.UTC)) {
		t.Errorf("folded entry %+v", tls)
	}

	for i := 0; i < 30; i++ {
		now = now.Add(time.Minute)
		u.add(fmt.Sprintf("h%02d.example.com", i), ReasonTooLarge)
	}
	counts, hosts = u.snapshot()
	if len(hosts) != maxUninspectableHosts {
		t.Fatalf("%d hosts, want %d", len(hosts), maxUninspectableHosts)
	}
	if hosts[0].Host != "h29.example.com" || hosts[len(hosts)-1].Host != "h10.example.com" {
		t.Errorf("kept %s … %s, want the 20 most recent", hosts[0].Host, hosts[len(hosts)-1].Host)
	}
	if counts[ReasonTooLarge] != 30 || counts[ReasonTLSUntrusted] != 3 {
		t.Errorf("counts must keep everything: %v", counts)
	}

	u.add(strings.Repeat("a", 400), ReasonTooLarge)
	if _, hosts = u.snapshot(); len(hosts[0].Host) != maxHostLen {
		t.Errorf("host kept at %d characters", len(hosts[0].Host))
	}
}

// The status leaves the fields out until something happened.
func TestUninspectable_OmittedWhenEmpty(t *testing.T) {
	b, _ := json.Marshal(Status{Redirect: "active", Proxy: ProxyHealthy})
	if strings.Contains(string(b), "uninspectable") {
		t.Errorf("empty status carries uninspectable fields: %s", b)
	}
}
