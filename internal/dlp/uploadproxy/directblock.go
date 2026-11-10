package uploadproxy

// Blocking direct connections to the inspected sites (#427, Windows): the
// PAC script only steers apps that honour the system proxy, so while the
// redirect is active the agent also blocks direct TCP and UDP 443 to the
// addresses the intercept hosts resolve to, except from its own process
// (it is the proxy). Apps that ignore the proxy then can't upload to those
// sites around the inspection, and browsers fall back from QUIC to TCP.
//
// It is enforcement, so it only runs when the files module isn't
// audit_only, and only while the redirect is active: when the proxy is
// down, the emergency switch is on or inspection stops, the block goes
// with the redirect. The filters live in a dynamic WFP session, so they
// also go when the agent dies.
//
// Addresses are best effort: they come from resolving the exact intercept
// hosts (a "*.example.com" pattern can't be resolved) and are refreshed on
// the DNS TTL; addresses a bypass host resolves to are never blocked. A CDN
// address shared with sites outside the list is blocked for them too, which
// is why the count is reported.

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// DirectBlocker blocks direct TCP and UDP 443 to a set of addresses, except
// from the agent's own process.
type DirectBlocker interface {
	// Set replaces the blocked addresses; an empty set blocks nothing.
	Set(addrs []netip.Addr) error
	// Close removes every block.
	Close() error
}

// Resolver resolves host to its addresses and how long they stay valid.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, time.Duration, error)

// Direct block states in the status.
const (
	DirectBlockActive    = "active"
	DirectBlockInactive  = "inactive"
	DirectBlockAuditOnly = "off:audit_only"
)

// DirectBlockStatus is the direct block in files.deep_inspection.
type DirectBlockStatus struct {
	State     string `json:"state"`     // active, inactive, off:audit_only, unsupported:<reason>
	Addresses int    `json:"addresses"` // blocked addresses
	// Unresolved counts intercept hosts with no address yet, and Patterns
	// the wildcard patterns that can't be blocked by address.
	Unresolved int `json:"unresolved"`
	Patterns   int `json:"patterns"`
}

// Address book tuning; vars for tests.
var (
	minDNSTTL       = 30 * time.Second
	maxDNSTTL       = 10 * time.Minute
	dnsRetry        = time.Minute
	addrRetention   = 30 * time.Minute // apps cache addresses past their TTL
	resolveTimeout  = 5 * time.Second
	maxBlockedAddrs = 2000
)

type hostEntry struct {
	addrs map[netip.Addr]time.Time // address -> last seen
	next  time.Time                // when to resolve again
}

// addressBook resolves hosts on their TTL and remembers recent addresses.
type addressBook struct {
	resolve Resolver
	now     func() time.Time
	hosts   map[string]*hostEntry
}

func newAddressBook(r Resolver) *addressBook {
	return &addressBook{resolve: r, now: time.Now, hosts: map[string]*hostEntry{}}
}

// refresh resolves the hosts that are due and forgets hosts not listed.
func (b *addressBook) refresh(ctx context.Context, hosts []string) {
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
func (b *addressBook) resolveInto(ctx context.Context, h string, e *hostEntry, now time.Time) {
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

// addrs returns the addresses of hosts, sorted.
func (b *addressBook) addrs(hosts []string) map[netip.Addr]bool {
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

// exactHosts splits a host list into exact names and a count of patterns.
func exactHosts(list []string) (hosts []string, patterns int) {
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

// directBlock keeps the blocker in step with the intercept hosts. update
// and stop run on the watchdog (or after it stopped); status from anywhere.
type directBlock struct {
	open func() (DirectBlocker, error)
	book *addressBook

	mu      sync.Mutex
	blocker DirectBlocker
	applied []netip.Addr
	st      DirectBlockStatus
}

func newDirectBlock(open func() (DirectBlocker, error), r Resolver) *directBlock {
	return &directBlock{open: open, book: newAddressBook(r), st: DirectBlockStatus{State: DirectBlockInactive}}
}

// update blocks the current addresses of intercept (less bypass's).
func (d *directBlock) update(ctx context.Context, intercept, bypass []string) {
	in, patterns := exactHosts(intercept)
	out, _ := exactHosts(bypass)
	d.book.refresh(ctx, append(slices.Clone(in), out...))
	keep := d.book.addrs(out)
	var addrs []netip.Addr
	for a := range d.book.addrs(in) {
		if !keep[a] {
			addrs = append(addrs, a)
		}
	}
	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	if len(addrs) > maxBlockedAddrs {
		addrs = addrs[:maxBlockedAddrs]
	}
	unresolved := 0
	for _, h := range in {
		if e := d.book.hosts[h]; e == nil || len(e.addrs) == 0 {
			unresolved++
		}
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	d.st.Unresolved, d.st.Patterns = unresolved, patterns
	if d.blocker == nil {
		b, err := d.open()
		if err != nil {
			d.st = DirectBlockStatus{State: unsupported + Reason(err), Unresolved: unresolved, Patterns: patterns}
			return
		}
		d.blocker, d.applied = b, nil
	}
	if d.applied != nil && slices.Equal(addrs, d.applied) {
		d.st.State, d.st.Addresses = DirectBlockActive, len(addrs)
		return
	}
	if err := d.blocker.Set(addrs); err != nil {
		d.closeLocked()
		d.st = DirectBlockStatus{State: unsupported + "error", Unresolved: unresolved, Patterns: patterns}
		return
	}
	if addrs == nil {
		addrs = []netip.Addr{}
	}
	d.applied = addrs
	d.st.State, d.st.Addresses = DirectBlockActive, len(addrs)
}

// stop removes every block; state says why (inactive, off:audit_only).
func (d *directBlock) stop(state string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closeLocked()
	d.st = DirectBlockStatus{State: state}
}

func (d *directBlock) closeLocked() {
	if d.blocker != nil {
		_ = d.blocker.Close()
		d.blocker, d.applied = nil, nil
	}
}

func (d *directBlock) status() DirectBlockStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.st
}
