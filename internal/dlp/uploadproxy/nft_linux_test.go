package uploadproxy

import (
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"sentinelgo/internal/binpath"
)

// The backstop end to end, with real nftables and conntrack (root, nft
// installed; CI runs it as root): a "site" on 127.0.0.2:443 is in the
// redirected set. A TLS client connecting to it directly lands in the
// proxy's transparent listener: the intercepted name is decrypted and its
// upload refused, another name on the same address is spliced through to
// the real server, and the proxy's own (marked) connections aren't
// redirected back to it. UDP 443 to the address is refused.
func TestNftBackstop_EndToEnd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: adds an nftables table")
	}
	if _, ok := binpath.Lookup("nft"); !ok {
		t.Skip("needs the nft command")
	}
	site := netip.MustParseAddrPort("127.0.0.2:443")
	up := &upstream{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 1<<10)
		n, _ := r.Body.Read(b)
		up.mu.Lock()
		up.got = append(up.got, b[:n])
		up.mu.Unlock()
		_, _ = w.Write([]byte("stored"))
	})
	l, err := net.Listen("tcp", site.String())
	if err != nil {
		t.Skipf("can't listen on %s: %v", site, err)
	}
	up.srv = &httptest.Server{Listener: l, Config: &http.Server{Handler: h}}
	up.srv.StartTLS()
	t.Cleanup(up.srv.Close)

	ls, ports, orig, err := platformTransparent()
	if err != nil {
		t.Fatal(err)
	}
	f := newTransparentFixture(t, up, bundle(false, "allow"), orig)
	f.proxy.dialer.Control = func(_, _ string, c syscall.RawConn) error { setMark(c, proxyMark); return nil }
	for _, tl := range ls {
		go func() { _ = f.proxy.ServeTransparent(tl, orig) }()
		t.Cleanup(func() { _ = tl.Close() })
	}
	f.at = site.String() // clients go to the site; nftables takes them to the proxy

	b, err := platformDirectBlocker(ports)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Errorf("remove the table: %v", err)
		}
	})
	if err := b.Set([]netip.Addr{site.Addr()}, true); err != nil {
		t.Fatal(err)
	}

	resp, st := f.do(t, "example.com", caPool(f.ca), http.MethodPost, "numbers TOPSECRET numbers")
	if resp.StatusCode != http.StatusForbidden || !isOurCAIssued(st.PeerCertificates[0]) {
		t.Fatalf("intercepted: status %d, issuer %s", resp.StatusCode, st.PeerCertificates[0].Issuer)
	}
	if resp, _ := f.do(t, "example.com", caPool(f.ca), http.MethodPost, "hello"); resp.StatusCode != http.StatusOK {
		t.Errorf("clean upload through the proxy: status %d (marked connections redirected back?)", resp.StatusCode)
	}
	roots := x509.NewCertPool()
	roots.AddCert(up.srv.Certificate())
	if resp, st := f.do(t, "www.example.com", roots, http.MethodPost, "other site"); resp.StatusCode != http.StatusOK ||
		!st.PeerCertificates[0].Equal(up.srv.Certificate()) {
		t.Errorf("other site: status %d", resp.StatusCode)
	}
	if s := f.proxy.Stats(); s.Intercepted != 2 || s.Tunnelled != 1 {
		t.Errorf("stats %+v", s)
	}

	// UDP 443 is refused: a datagram never reaches a listener there.
	pc, err := net.ListenPacket("udp", site.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	c, err := net.Dial("udp", site.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, werr := c.Write([]byte("quic"))
	_ = pc.SetReadDeadline(time.Now().Add(time.Second))
	if n, _, err := pc.ReadFrom(make([]byte, 16)); err == nil {
		t.Errorf("UDP 443 got through (%d bytes, write error %v)", n, werr)
	}

	// Closing removes the table: the site is reached directly again.
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if resp, st := f.do(t, "example.com", roots, http.MethodPost, "after"); resp.StatusCode != http.StatusOK ||
		!st.PeerCertificates[0].Equal(up.srv.Certificate()) {
		t.Errorf("after removal: status %d", resp.StatusCode)
	}
	if err := runNft("list table inet " + nftTable + "\n"); err == nil || errors.Is(err, ErrNoNft) {
		t.Errorf("table still there after Close (%v)", err)
	}
}

func isOurCAIssued(c *x509.Certificate) bool {
	return len(c.Issuer.Organization) == 1 && c.Issuer.Organization[0] == "SentinelOps"
}
