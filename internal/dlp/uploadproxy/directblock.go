package uploadproxy

// Blocking direct connections to the inspected sites (#427, Windows): the
// PAC script only steers apps that honour the system proxy, so while the
// redirect is active the agent also blocks direct 443 to the addresses the
// intercept hosts resolve to, except from its own process (it is the
// proxy). How much is blocked is the policy's direct_block mode (#451):
//
//   - quic (default): UDP 443 only. QUIC clients fall back to TCP, and TCP
//     follows the PAC into the proxy. A shared CDN address costs other
//     sites HTTP/3, not reachability.
//   - strict: TCP and UDP 443. Apps that ignore the proxy can't upload to
//     the sites around the inspection, but every site sharing an address
//     with them breaks too, as do browsers before the PAC applies (WPAD
//     resolves to DIRECT first) and the PAC's DIRECT fallback.
//   - off: no block, the PAC only.
//
// The same rule holds for the later backstops (Linux nftables, macOS pf):
// no TCP block by address for all processes except in strict.
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
// address shared with sites outside the list is blocked for them too (in
// strict, for TCP as well), which is why the count is reported.

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"sentinelgo/internal/dlp/policy"
)

// DirectBlocker blocks direct UDP 443, and TCP 443 when asked, to a set of
// addresses, except from the agent's own process.
type DirectBlocker interface {
	// Set replaces the blocked addresses and protocols; an empty set blocks
	// nothing.
	Set(addrs []netip.Addr, tcp bool) error
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
	DirectBlockOff       = "off:policy" // direct_block is "off"
)

// DirectBlockStatus is the direct block in files.deep_inspection.
type DirectBlockStatus struct {
	State string `json:"state"` // active, inactive, off:audit_only, off:policy, unsupported:<reason>
	// Mode is the policy's direct_block (quic, strict, off), and Protocols
	// what is blocked while active: ["udp"] or ["tcp","udp"].
	Mode      string   `json:"mode"`
	Protocols []string `json:"protocols,omitempty"`
	Addresses int      `json:"addresses"` // blocked addresses
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

	mu         sync.Mutex
	blocker    DirectBlocker
	applied    []netip.Addr
	appliedTCP bool
	st         DirectBlockStatus
}

func newDirectBlock(open func() (DirectBlocker, error), r Resolver) *directBlock {
	return &directBlock{open: open, book: newAddressBook(r),
		st: DirectBlockStatus{State: DirectBlockInactive, Mode: policy.DirectBlockQUIC}}
}

// update blocks the current addresses of intercept (less bypass's) in mode
// (policy.DirectBlockQUIC or DirectBlockStrict; DirectBlockOff stops).
func (d *directBlock) update(ctx context.Context, intercept, bypass []string, mode string) {
	if mode == policy.DirectBlockOff {
		d.stop(DirectBlockOff, mode)
		return
	}
	tcp := mode == policy.DirectBlockStrict
	protocols := []string{"udp"}
	if tcp {
		protocols = []string{"tcp", "udp"}
	}
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
	failed := func(state string) DirectBlockStatus {
		return DirectBlockStatus{State: state, Mode: mode, Unresolved: unresolved, Patterns: patterns}
	}
	if d.blocker == nil {
		b, err := d.open()
		if err != nil {
			d.st = failed(unsupported + Reason(err))
			return
		}
		d.blocker, d.applied = b, nil
	}
	if d.applied == nil || !slices.Equal(addrs, d.applied) || tcp != d.appliedTCP {
		if err := d.blocker.Set(addrs, tcp); err != nil {
			d.closeLocked()
			d.st = failed(unsupported + "error")
			return
		}
		if addrs == nil {
			addrs = []netip.Addr{}
		}
		d.applied, d.appliedTCP = addrs, tcp
	}
	d.st = DirectBlockStatus{State: DirectBlockActive, Mode: mode, Protocols: protocols,
		Addresses: len(addrs), Unresolved: unresolved, Patterns: patterns}
}

// stop removes every block; state says why (inactive, off:audit_only,
// off:policy) and mode is the policy's direct_block.
func (d *directBlock) stop(state, mode string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closeLocked()
	d.st = DirectBlockStatus{State: state, Mode: mode}
}

func (d *directBlock) closeLocked() {
	if d.blocker != nil {
		_ = d.blocker.Close()
		d.blocker, d.applied, d.appliedTCP = nil, nil, false
	}
}

func (d *directBlock) status() DirectBlockStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.st
}
