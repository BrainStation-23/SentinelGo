//go:build windows && (amd64 || arm64)

package uploadproxy

import (
	"net/netip"
	"testing"
)

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
