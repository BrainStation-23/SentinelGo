//go:build !windows

package addrbook

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// System asks Go's resolver, which doesn't report TTLs: the Book then looks
// again after minDNSTTL and keeps addresses for addrRetention.
func System(ctx context.Context, host string) ([]netip.Addr, time.Duration, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	return addrs, 0, err
}
