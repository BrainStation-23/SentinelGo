//go:build windows && (amd64 || arm64)

package netctl

import (
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

// The WFP ruleset end to end (elevated; the CI Windows runner is): the test
// binary blocks itself, so its connections to a local non-loopback address
// are refused, loopback still works, an allowed destination gets through,
// and closing removes the block. The filters are in a dynamic session, so
// they go with the test process whatever happens.
func TestWFPRuleset(t *testing.T) {
	w, err := openWFP()
	if err != nil {
		t.Skipf("WFP (needs elevation): %v", err)
	}
	defer func() { _ = w.Close() }()
	ip := localIPv4(t)
	far := listen(t, netip.AddrPortFrom(ip, 0).String())
	near := listen(t, "127.0.0.1:0")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	if err := w.Set(Rules{BlockApps: []string{self}}); err != nil {
		t.Fatal(err)
	}
	if dial(far) == nil {
		t.Errorf("a blocked app reached %s", far)
	}
	if err := dial(near); err != nil {
		t.Errorf("loopback refused for a blocked app: %v", err)
	}

	if err := w.Set(Rules{BlockApps: []string{self}, Allow: []netip.Prefix{netip.PrefixFrom(ip, 32)}}); err != nil {
		t.Fatal(err)
	}
	if err := dial(far); err != nil {
		t.Errorf("allowed destination refused: %v", err)
	}

	if err := w.Set(Rules{BlockApps: []string{self}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := dial(far); err != nil {
		t.Errorf("still blocked after Close: %v", err)
	}
}

func localIPv4(t *testing.T) netip.Addr {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skip(err)
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP.To4()); ok && n.IP.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				return ip
			}
		}
	}
	t.Skip("no non-loopback IPv4 address")
	return netip.Addr{}
}

func listen(t *testing.T, addr string) string {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return l.Addr().String()
}

func dial(addr string) error {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	return c.Close()
}
