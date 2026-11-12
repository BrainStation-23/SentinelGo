// Package addrbook keeps the addresses of a list of host names current:
// each host is resolved again when its DNS TTL runs out, and addresses stay
// for a while after they were last seen, because apps cache them past the
// TTL. The upload proxy's direct block (#426, #427) and the network
// controls (#427) turn host names into firewall rules with it.
package addrbook

import (
	"context"
	"net/netip"
	"strings"
	"time"
)

// Resolver resolves host to its addresses and how long they stay valid.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, time.Duration, error)

// Tuning; vars for tests.
var (
	minDNSTTL       = 30 * time.Second
	maxDNSTTL       = 10 * time.Minute
	dnsRetry        = time.Minute
	addrRetention   = 30 * time.Minute // apps cache addresses past their TTL
	resolveTimeout  = 5 * time.Second
)

type hostEntry struct {
	addrs map[netip.Addr]time.Time // address -> last seen
	next  time.Time                // when to resolve again
}

// Book resolves hosts on their TTL and remembers recent addresses. It is
// not safe for concurrent use.
type Book struct {
	resolve Resolver
	now     func() time.Time
	hosts   map[string]*hostEntry
}

// New returns a Book that resolves with r.
func New(r Resolver) *Book {
	return &Book{resolve: r, now: time.Now, hosts: map[string]*hostEntry{}}
}

// Refresh resolves the hosts that are due and forgets hosts not listed.
func (b *Book) Refresh(ctx context.Context, hosts []string) {
	want := map[string]bool{}
	for _, h := range hosts {
		want[h] = true
	}
	for h := range b.hosts {
		if !want[h] {
			delete(b.hosts, h)
		}
	}
	now := b.now()
	for _, h := range hosts {
		e := b.hosts[h]
		if e == nil {
			e = &hostEntry{addrs: map[netip.Addr]time.Time{}}
			b.hosts[h] = e
		}
		if !now.Before(e.next) {
			b.resolveInto(ctx, h, e, now)
		}
	}
}

// resolveInto resolves h, records its addresses as seen now, schedules the
// next lookup and forgets addresses not seen for addrRetention.
func (b *Book) resolveInto(ctx context.Context, h string, e *hostEntry, now time.Time) {
	rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	addrs, ttl, err := b.resolve(rctx, h)
	cancel()
	e.next = now.Add(dnsRetry)
	if err == nil {
		for _, a := range addrs {
			e.addrs[a.Unmap()] = now
		}
		e.next = now.Add(min(max(ttl, minDNSTTL), maxDNSTTL))
	}
	for a, seen := range e.addrs {
		if now.Sub(seen) > addrRetention {
			delete(e.addrs, a)
		}
	}
}

// Addrs returns the addresses of hosts.
func (b *Book) Addrs(hosts []string) map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	for _, h := range hosts {
		if e := b.hosts[h]; e != nil {
			for a := range e.addrs {
				out[a] = true
			}
		}
	}
	return out
}

// ExactHosts splits a host list into exact names (lower case) and a count
// of "*." patterns, which can't be resolved.
func ExactHosts(list []string) (hosts []string, patterns int) {
	for _, h := range list {
		h = strings.ToLower(strings.TrimSpace(h))
		switch {
		case h == "":
		case strings.HasPrefix(h, "*."):
			patterns++
		default:
			hosts = append(hosts, h)
		}
	}
	return hosts, patterns
}

// Unresolved counts the hosts with no address yet.
func (b *Book) Unresolved(hosts []string) int {
	n := 0
	for _, h := range hosts {
		if e := b.hosts[h]; e == nil || len(e.addrs) == 0 {
			n++
		}
	}
	return n
}
