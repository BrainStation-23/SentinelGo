//go:build windows && (amd64 || arm64)

package uploadproxy

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// The DNS client resolves through its cache and reports a TTL.
func TestDNSResolve(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, ttl, err := dnsResolve(ctx, "localhost")
	if err != nil {
		t.Skipf("DNS client: %v", err)
	}
	found := false
	for _, a := range addrs {
		found = found || a.IsLoopback()
	}
	if !found || ttl <= 0 {
		t.Errorf("localhost: %v ttl %v", addrs, ttl)
	}
	// A missing name has no addresses; resolvers differ on whether that's
	// an error (the address book retries either way).
	if addrs, _, _ = dnsResolve(ctx, "does-not-exist.invalid"); len(addrs) != 0 {
		t.Errorf("missing name: %v", addrs)
	}
}

// Without elevation the WFP blocker can't add its filters; with it (the CI
// runner) it opens, blocks and closes.
func TestWFPBlocker(t *testing.T) {
	b, err := newWFPBlocker()
	if err != nil {
		t.Skipf("WFP blocker (needs elevation): %v", err)
	}
	addrs := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}
	for _, tcp := range []bool{false, true, false} { // quic, strict, quic: swapped in place
		if err := b.Set(addrs, tcp); err != nil {
			t.Fatalf("tcp %v: %v", tcp, err)
		}
		if len(b.ids) != 2 {
			t.Errorf("tcp %v: filters %v", tcp, b.ids)
		}
	}
	if err := b.Set(nil, false); err != nil || len(b.ids) != 0 {
		t.Fatalf("clear: %v %v", err, b.ids)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
}
