package uploadproxy

// Blocking direct connections to the inspected sites (Windows: WFP, #427;
// Linux: nftables, #426): the PAC script only steers apps that honour the
// system proxy, so while the redirect is active the agent also blocks
// direct 443 to the addresses the intercept hosts resolve to, except from
// its own process (it is the proxy). How much is blocked is the policy's
// direct_block mode (#451):
//
//   - quic (default): UDP 443 only. QUIC clients fall back to TCP, and TCP
//     follows the PAC into the proxy. A shared CDN address costs other
//     sites HTTP/3, not reachability.
//   - strict: TCP 443 too. On Windows it is refused: apps that ignore the
//     proxy can't upload to the sites around the inspection, but every
//     site sharing an address with them breaks too, as do browsers before
//     the PAC applies (WPAD resolves to DIRECT first) and the PAC's DIRECT
//     fallback. On Linux it is redirected into the proxy's transparent
//     listener instead (transparent.go), which inspects the intercepted
//     hosts by SNI and passes every other site through, so shared
//     addresses cost nothing but the hop.
//   - off: no block, the PAC only.
//
// The same rule holds for a later macOS pf backstop: no TCP block by
// address for all processes except in strict.
//
// It is enforcement, so it only runs when the files module isn't
// audit_only, and only while the redirect is active: when the proxy is
// down, the emergency switch is on or inspection stops, the block goes
// with the redirect. WFP filters live in a dynamic session, so they also go
// when the agent dies; the nftables table doesn't, so it is removed on the
// next start and on uninstall (platformDirectCleanup).
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
	"sync"

	"sentinelgo/internal/dlp/addrbook"
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

// tcpActioner is a DirectBlocker that says what it does with TCP 443
// (TCPRefuse or TCPRedirect); blockers that don't refuse it.
type tcpActioner interface{ TCPAction() string }

// Resolver resolves host to its addresses and how long they stay valid.
type Resolver = addrbook.Resolver

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
	// TCP is what happens to TCP 443 when it is in Protocols: refuse
	// (Windows) or redirect into the proxy (Linux).
	TCP       string `json:"tcp,omitempty"`
	Addresses int    `json:"addresses"` // blocked addresses
	// Unresolved counts intercept hosts with no address yet, and Patterns
	// the wildcard patterns that can't be blocked by address.
	Unresolved int `json:"unresolved"`
	Patterns   int `json:"patterns"`
}

// maxBlockedAddrs bounds the blocked addresses; a var for tests.
var maxBlockedAddrs = 2000

// directBlock keeps the blocker in step with the intercept hosts. update
// and stop run on the watchdog (or after it stopped); status from anywhere.
type directBlock struct {
	open func() (DirectBlocker, error)
	book *addrbook.Book

	mu         sync.Mutex
	blocker    DirectBlocker
	applied    []netip.Addr
	appliedTCP bool
	st         DirectBlockStatus
}

func newDirectBlock(open func() (DirectBlocker, error), r Resolver) *directBlock {
	return &directBlock{open: open, book: addrbook.New(r),
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
	in, patterns := addrbook.ExactHosts(intercept)
	out, _ := addrbook.ExactHosts(bypass)
	d.book.Refresh(ctx, append(slices.Clone(in), out...))
	keep := d.book.Addrs(out)
	var addrs []netip.Addr
	for a := range d.book.Addrs(in) {
		if !keep[a] {
			addrs = append(addrs, a)
		}
	}
	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	if len(addrs) > maxBlockedAddrs {
		addrs = addrs[:maxBlockedAddrs]
	}
	unresolved := d.book.Unresolved(in)

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
	if tcp {
		d.st.TCP = TCPRefuse
		if a, ok := d.blocker.(tcpActioner); ok {
			d.st.TCP = a.TCPAction()
		}
	}
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
