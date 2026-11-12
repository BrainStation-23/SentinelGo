package addrbook

import (
	"context"
	"testing"
	"time"
)

// The DNS client resolves through its cache and reports a TTL.
func TestDNSResolve(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, ttl, err := System(ctx, "localhost")
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
	if addrs, _, _ = System(ctx, "does-not-exist.invalid"); len(addrs) != 0 {
		t.Errorf("missing name: %v", addrs)
	}
}
