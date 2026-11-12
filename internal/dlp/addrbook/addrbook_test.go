package addrbook

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakeDNS answers from a map and counts lookups.
type fakeDNS struct {
	mu      sync.Mutex
	answers map[string][]string
	ttl     time.Duration
	fail    map[string]bool
	lookups map[string]int
}

func newFakeDNS() *fakeDNS {
	return &fakeDNS{answers: map[string][]string{}, ttl: time.Minute, fail: map[string]bool{}, lookups: map[string]int{}}
}

func (f *fakeDNS) set(host string, addrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[host] = addrs
}

func (f *fakeDNS) resolve(_ context.Context, host string) ([]netip.Addr, time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups[host]++
	if f.fail[host] {
		return nil, 0, errors.New("servfail")
	}
	var out []netip.Addr
	for _, a := range f.answers[host] {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, f.ttl, nil
}

func TestAddressBook(t *testing.T) {
	dns := newFakeDNS()
	dns.set("a.example", "192.0.2.1", "2001:db8::1")
	b := New(dns.resolve)
	now := time.Unix(1_000_000, 0)
	b.now = func() time.Time { return now }

	b.Refresh(context.Background(), []string{"a.example"})
	if got := len(b.Addrs([]string{"a.example"})); got != 2 {
		t.Fatalf("addrs %d", got)
	}
	// Not due before the TTL; due after.
	now = now.Add(30 * time.Second)
	b.Refresh(context.Background(), []string{"a.example"})
	if dns.lookups["a.example"] != 1 {
		t.Errorf("looked up before the TTL: %d", dns.lookups["a.example"])
	}
	now = now.Add(31 * time.Second)
	dns.set("a.example", "192.0.2.2") // the CDN moved
	b.Refresh(context.Background(), []string{"a.example"})
	if got := b.Addrs([]string{"a.example"}); len(got) != 3 || !got[netip.MustParseAddr("192.0.2.1")] {
		t.Errorf("old addresses kept for a while: %v", got)
	}
	// Past the retention the old ones go.
	for range 40 {
		now = now.Add(time.Minute)
		b.Refresh(context.Background(), []string{"a.example"})
	}
	if got := b.Addrs([]string{"a.example"}); len(got) != 1 || !got[netip.MustParseAddr("192.0.2.2")] {
		t.Errorf("after retention: %v", got)
	}
	// A failure retries after dnsRetry; an unlisted host is forgotten.
	dns.fail["b.example"] = true
	b.Refresh(context.Background(), []string{"b.example"})
	if _, ok := b.hosts["a.example"]; ok {
		t.Error("unlisted host kept")
	}
	if b.hosts["b.example"].next != now.Add(dnsRetry) {
		t.Error("failure not retried after dnsRetry")
	}
	// The TTL is clamped.
	dns.ttl = time.Second
	dns.set("c.example", "192.0.2.9")
	b.Refresh(context.Background(), []string{"c.example"})
	if b.hosts["c.example"].next != now.Add(minDNSTTL) {
		t.Error("short TTL not clamped")
	}
}

func TestExactHosts(t *testing.T) {
	hosts, patterns := ExactHosts([]string{" Drive.Example.com ", "*.dropbox.com", "", "x.example"})
	if len(hosts) != 2 || hosts[0] != "drive.example.com" || patterns != 1 {
		t.Errorf("hosts %v patterns %d", hosts, patterns)
	}
}
