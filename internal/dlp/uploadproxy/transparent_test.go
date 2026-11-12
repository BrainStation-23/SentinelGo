package uploadproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// transparentFixture serves the fixture's proxy in transparent mode: every
// connection "was going to" up (the fake conntrack answer), and the proxy's
// upstream dials for intercepted hosts land on up too.
type transparentFixture struct {
	*fixture
	at string // the transparent listener
	up *upstream
}

func newTransparentFixture(t *testing.T, up *upstream, bundleJSON string, orig OriginalDst) *transparentFixture {
	t.Helper()
	f := newFixture(t, up, bundleJSON, nil)
	upAddr := up.srv.Listener.Addr().String()
	f.proxy.opts.InScope = func(host, _ string) bool { return host == "example.com" }
	f.proxy.transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return f.proxy.dialer.DialContext(ctx, network, upAddr)
	}
	if orig == nil {
		orig = func(net.Conn) (netip.AddrPort, error) { return netip.ParseAddrPort(upAddr) }
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() { _ = f.proxy.ServeTransparent(l, orig) }()
	return &transparentFixture{fixture: f, at: l.Addr().String(), up: up}
}

// do sends one HTTP/1.1 request over TLS to the transparent listener, as an
// app connecting "directly" to sni would.
func (f *transparentFixture) do(t *testing.T, sni string, roots *x509.CertPool, method, body string) (*http.Response, *tls.ConnectionState) {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", f.at,
		&tls.Config{ServerName: sni, RootCAs: roots, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatalf("TLS to the transparent listener: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_, _ = fmt.Fprintf(conn, "%s /upload HTTP/1.1\r\nHost: %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		method, sni, len(body), body)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("response: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	st := conn.ConnectionState()
	return resp, &st
}

func caPool(ca *CA) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Certificate())
	return p
}

// An intercepted host (by SNI) is decrypted with a leaf for that host and
// its uploads inspected: a sensitive one is refused, a clean one forwarded.
func TestTransparent_InterceptsBySNI(t *testing.T) {
	up := newUpstream(t, true)
	f := newTransparentFixture(t, up, bundle(false, "allow"), nil)

	resp, st := f.do(t, "example.com", caPool(f.ca), http.MethodPost, "numbers TOPSECRET numbers")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("sensitive upload: status %d", resp.StatusCode)
	}
	if leaf := st.PeerCertificates[0]; leaf.VerifyHostname("example.com") != nil || !strings.HasPrefix(leaf.Issuer.CommonName, caSubjectPrefix) {
		t.Errorf("leaf %s from %s", leaf.Subject, leaf.Issuer)
	}
	if len(up.received()) != 0 {
		t.Error("the sensitive upload reached the site")
	}
	if resp, _ := f.do(t, "example.com", caPool(f.ca), http.MethodPost, "hello"); resp.StatusCode != http.StatusOK || len(up.received()) != 1 {
		t.Errorf("clean upload: status %d, site got %d", resp.StatusCode, len(up.received()))
	}
	if s := f.proxy.Stats(); s.Intercepted != 2 || s.Blocked != 1 || s.Tunnelled != 0 {
		t.Errorf("stats %+v", s)
	}
}

// Any other site on the redirected addresses is spliced through to where it
// was going: the client talks TLS with the real server, nothing inspected.
func TestTransparent_PassesOtherSitesThrough(t *testing.T) {
	up := newUpstream(t, true)
	f := newTransparentFixture(t, up, bundle(false, "allow"), nil)
	roots := x509.NewCertPool()
	roots.AddCert(up.srv.Certificate())
	resp, st := f.do(t, "www.example.com", roots, http.MethodPost, "numbers TOPSECRET numbers")
	if resp.StatusCode != http.StatusOK || !st.PeerCertificates[0].Equal(up.srv.Certificate()) {
		t.Fatalf("status %d, peer %s", resp.StatusCode, st.PeerCertificates[0].Subject)
	}
	if got := up.received(); len(got) != 1 || string(got[0]) != "numbers TOPSECRET numbers" {
		t.Errorf("site got %q", got)
	}
	if s := f.proxy.Stats(); s.Tunnelled != 1 || s.Intercepted != 0 || len(f.sink.events()) != 0 {
		t.Errorf("stats %+v, %d events", s, len(f.sink.events()))
	}
}

// Bytes that aren't TLS are replayed to the original destination as they
// came, so a non-TLS protocol on 443 still works.
func TestTransparent_NonTLSPassesThrough(t *testing.T) {
	up := newUpstream(t, false)
	f := newTransparentFixture(t, up, bundle(false, "allow"), nil)
	conn, err := net.Dial("tcp", f.at)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = io.WriteString(conn, "POST /x HTTP/1.1\r\nHost: plain\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(up.received()) != 1 || string(up.received()[0]) != "hello" {
		t.Errorf("status %d, site got %q", resp.StatusCode, up.received())
	}
}

// A connection that wasn't redirected (no conntrack answer, or one pointing
// at the listener itself) is closed without being forwarded anywhere.
func TestTransparent_RefusesUnredirected(t *testing.T) {
	up := newUpstream(t, true)
	for name, orig := range map[string]OriginalDst{
		"no original destination": func(net.Conn) (netip.AddrPort, error) { return netip.AddrPort{}, errors.New("ENOENT") },
		"the listener itself":     func(c net.Conn) (netip.AddrPort, error) { return c.LocalAddr().(*net.TCPAddr).AddrPort(), nil },
	} {
		t.Run(name, func(t *testing.T) {
			f := newTransparentFixture(t, up, bundle(false, "allow"), orig)
			conn, err := net.Dial("tcp", f.at)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			if n, err := conn.Read(make([]byte, 1)); n != 0 || err == nil {
				t.Errorf("read %d, %v; want the connection closed", n, err)
			}
			if f.proxy.Stats().Errors != 1 {
				t.Errorf("stats %+v", f.proxy.Stats())
			}
		})
	}
}

// Peeking stops at the size limit instead of buffering a client forever.
func TestPeekClientHello_Limits(t *testing.T) {
	defer func(n int) { maxHelloBytes = n }(maxHelloBytes)
	maxHelloBytes = 64
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	go func() { _, _ = a.Write([]byte{0x16, 0x03, 0x01, 0x40, 0x00}); _, _ = a.Write(make([]byte, 1000)) }()
	sni, read := peekClientHello(b)
	if sni != "" || len(read) > 64 {
		t.Errorf("sni %q, read %d bytes", sni, len(read))
	}
}
