// Package devicectx implements Phase 4's background context collector: an
// epm.ContextProvider whose Snapshot() is a single atomic pointer load plus a
// struct copy, safe to call on every elevation request, while actual
// collection happens on a background goroutine on independent cadences.
//
// Deliberately a separate package from internal/epm (which declares
// ContextSnapshot and the ContextProvider interface it implements): this
// package imports internal/osinfo/security and other collector packages,
// while internal/epm never imports this package — main_integration.go is
// where the two are wired together (epm.NewEngineWithSet(...,
// epm.WithContextProvider(devicectx.New(...)))). That keeps the policy
// engine's own dependency footprint (and test suite) small regardless of how
// much collection machinery this package eventually grows.
package devicectx

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"sentinelgo/internal/epm"
)

// Default collection cadences. osinfo.Collect can take up to 90s in the
// heartbeat path (scheduler.go's collectTimeout) — these tiers exist
// specifically so that cost never touches the elevation request path, which
// only ever does an atomic load.
const (
	DefaultSlowInterval    = 15 * time.Minute // posture: disk encryption, secure boot, firewall, AV, TPM, compliance, domain/Entra join
	DefaultNetworkInterval = 60 * time.Second // network type, VPN, corporate-network classification

	// postureCollectTimeout/networkCollectTimeout bound a single collection
	// attempt; a collector that hangs past this is treated as a failure for
	// that cycle (source marked stale/failed) rather than blocking the next
	// tick indefinitely.
	postureCollectTimeout = 60 * time.Second
	networkCollectTimeout = 10 * time.Second
	// coldStartTimeout bounds Start's synchronous fast-subset collection —
	// see Start's doc comment.
	coldStartTimeout = 5 * time.Second
)

// postureCollectorFn/networkCollectorFn/joinCollectorFn are seams so tests
// can substitute fast, deterministic fakes instead of the real (slow,
// platform-dependent, side-effecting) collectors — matching the
// package-level function-var pattern already established throughout
// internal/epm (e.g. launcher_iface_windows.go's computeFileHashFn).
var (
	postureCollectorFn = collectPostureReal
	networkCollectorFn = collectNetworkReal
	joinCollectorFn    = collectJoinReal
)

// Provider is a background-collecting epm.ContextProvider.
type Provider struct {
	snap atomic.Pointer[epm.ContextSnapshot]

	slowInterval    time.Duration
	networkInterval time.Duration
	defaults        epm.Defaults

	cancel context.CancelFunc
	done   chan struct{}
}

// Option configures a Provider.
type Option func(*Provider)

func WithSlowInterval(d time.Duration) Option    { return func(p *Provider) { p.slowInterval = d } }
func WithNetworkInterval(d time.Duration) Option { return func(p *Provider) { p.networkInterval = d } }

// WithDefaults supplies the tenant's corporate-network/VPN definitions
// (Defaults.CorporateDNSSuffixes etc. — see internal/epm/bundle.go) that the
// network collector classifies against. Without this, every network
// condition still collects (network type, gateways, DNS suffixes) but
// CorporateNetwork/VPNActive stay Unknown, since there is nothing to compare
// against — the same fail-closed default as no ContextProvider at all.
func WithDefaults(d epm.Defaults) Option { return func(p *Provider) { p.defaults = d } }

// New builds a Provider. Call Start to begin collection; before Start (or if
// Start is never called), Snapshot returns the zero ContextSnapshot, making
// every context-sourced condition Unknown — identical to no provider being
// wired at all.
func New(opts ...Option) *Provider {
	p := &Provider{slowInterval: DefaultSlowInterval, networkInterval: DefaultNetworkInterval}
	for _, opt := range opts {
		opt(p)
	}
	p.snap.Store(&epm.ContextSnapshot{})
	return p
}

// Snapshot implements epm.ContextProvider. Never blocks, never errors, never
// performs I/O — exactly the contract EvaluateV2 depends on.
func (p *Provider) Snapshot() epm.ContextSnapshot {
	return *p.snap.Load()
}

// Start begins background collection. Before returning, it runs a
// coldStartTimeout-bounded synchronous pass of the cheap network tier (and,
// through it, join state, which the real network collector's timeout budget
// covers) so the very first elevation request after startup is not served
// against a totally empty snapshot; the slow (posture) tier is intentionally
// NOT part of the cold-start pass — it can take up to postureCollectTimeout
// on its own, which would make every agent startup wait on it. Anything not
// collected within the cold-start window simply stays Unknown, exactly like
// any other cold start; Unknown fails closed (see matchers_context.go), so
// this is safe, only less permissive until the first background cycle
// completes.
func (p *Provider) Start(ctx context.Context) {
	runCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.done = make(chan struct{})

	coldCtx, coldCancel := context.WithTimeout(runCtx, coldStartTimeout)
	p.collectNetwork(coldCtx)
	coldCancel()

	go p.loop(runCtx)
}

// Stop cancels background collection and waits for the loop to exit.
func (p *Provider) Stop() {
	if p.cancel == nil {
		return
	}
	p.cancel()
	<-p.done
}

func (p *Provider) loop(ctx context.Context) {
	defer close(p.done)

	slowTicker := time.NewTicker(p.slowInterval)
	defer slowTicker.Stop()
	netTicker := time.NewTicker(p.networkInterval)
	defer netTicker.Stop()

	// Run the slow tier once immediately too, in its own goroutine so it
	// cannot delay the network ticker loop below from starting — waiting a
	// full slowInterval (default 15m) before the first posture collection
	// would leave every posture condition Unknown for a long time after a
	// fresh install or restart. A WaitGroup (rather than a fully detached
	// go statement) still ties its lifetime to loop's: the deferred Wait
	// below runs before deferred close(p.done) (defers unwind LIFO), so
	// Stop's "<-p.done" cannot unblock while this goroutine might still be
	// about to call p.update — without that, Stop() could return while a
	// collection result was still landing, which is exactly the kind of
	// "stopped but not really" gap Stop's own doc comment promises not to
	// have.
	var initialPosture sync.WaitGroup
	initialPosture.Add(1)
	go func() {
		defer initialPosture.Done()
		p.collectPosture(ctx)
	}()
	defer initialPosture.Wait()

	for {
		select {
		case <-ctx.Done():
			return
		case <-slowTicker.C:
			p.collectPosture(ctx)
		case <-netTicker.C:
			p.collectNetwork(ctx)
		}
	}
}

// update applies fn to a copy of the current snapshot and stores the result
// — a read-modify-write that is safe without additional locking because
// collectPosture/collectNetwork (the only writers besides Start's one
// synchronous cold-start call, which always happens-before loop starts) are
// only ever invoked serially from the single loop goroutine, or from Start
// before that goroutine exists.
func (p *Provider) update(fn func(*epm.ContextSnapshot)) {
	cur := *p.snap.Load()
	// cur is a shallow copy: cur.Sources still points at the SAME map
	// instance a concurrent Snapshot() caller may be holding right now (the
	// whole point of Snapshot() being an atomic pointer load is that the
	// struct it returns never changes underneath the caller). fn below
	// mutates Sources in place (Sources[key] = ...), so it must run against
	// a fresh clone, never the previous generation's map — otherwise this
	// is a live "concurrent map read and map write" between this
	// (single-writer) loop goroutine and any request-path goroutine calling
	// Snapshot(). Cloning also doubles as nil-initialization for the very
	// first collection on a freshly New()'d Provider, whose Sources starts
	// nil.
	cloned := make(map[string]epm.SourceState, len(cur.Sources))
	for k, v := range cur.Sources {
		cloned[k] = v
	}
	cur.Sources = cloned

	fn(&cur)
	cur.CollectedAt = time.Now().UTC()
	p.snap.Store(&cur)
}

func (p *Provider) markSourceFailed(key, errMsg string) {
	p.update(func(s *epm.ContextSnapshot) {
		s.Sources[key] = epm.SourceState{CollectedAt: time.Now().UTC(), OK: false, Err: errMsg}
	})
}

func (p *Provider) collectPosture(ctx context.Context) {
	resultCh := make(chan postureResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				resultCh <- postureResult{err: recoveredErr(r)}
			}
		}()
		resultCh <- postureCollectorFn()
	}()

	select {
	case res := <-resultCh:
		if res.err != nil {
			log.Printf("epm: devicectx: posture collection failed: %v", res.err)
			p.markSourceFailed("posture", res.err.Error())
			return
		}
		p.update(func(s *epm.ContextSnapshot) {
			s.DiskEncryption = res.diskEncryption
			s.SecureBoot = res.secureBoot
			s.FirewallState = res.firewallState
			s.AntivirusHealth = res.antivirusHealth
			s.Compliance = res.compliance
			s.TPMStatus = res.tpmStatus
			// OSVersion is read by osVersionMatcher under the "posture" source
			// (matchers_context.go), not "join" — it comes from the same slow
			// collection pass even though collectJoinReal is what fills it in,
			// since host OS version is cheap to read alongside domain/Entra
			// join state and does not deserve its own cadence/source key.
			s.OSVersion = res.osVersion
			s.Sources["posture"] = epm.SourceState{CollectedAt: time.Now().UTC(), OK: true}
		})

		join := joinCollectorFn()
		p.update(func(s *epm.ContextSnapshot) {
			s.DomainJoined = join.domainJoined
			s.DomainName = join.domainName
			s.EntraJoined = join.entraJoined
			s.TenantID = join.tenantID
			s.Sources["join"] = epm.SourceState{CollectedAt: time.Now().UTC(), OK: join.ok, Err: join.errMsg}
		})
	case <-time.After(postureCollectTimeout):
		log.Printf("epm: devicectx: posture collection timed out after %s", postureCollectTimeout)
		p.markSourceFailed("posture", "timed out")
	case <-ctx.Done():
	}
}

func (p *Provider) collectNetwork(ctx context.Context) {
	resultCh := make(chan networkResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				resultCh <- networkResult{err: recoveredErr(r)}
			}
		}()
		resultCh <- networkCollectorFn(p.defaults)
	}()

	select {
	case res := <-resultCh:
		if res.err != nil {
			log.Printf("epm: devicectx: network collection failed: %v", res.err)
			p.markSourceFailed("network", res.err.Error())
			return
		}
		p.update(func(s *epm.ContextSnapshot) {
			s.NetworkType = res.networkType
			s.VPNActive = res.vpnActive
			s.CorporateNetwork = res.corporateNetwork
			s.DNSSuffixes = res.dnsSuffixes
			s.Gateways = res.gateways
			s.SSID = res.ssid
			s.Sources["network"] = epm.SourceState{CollectedAt: time.Now().UTC(), OK: true}
		})
	case <-time.After(networkCollectTimeout):
		log.Printf("epm: devicectx: network collection timed out after %s", networkCollectTimeout)
		p.markSourceFailed("network", "timed out")
	case <-ctx.Done():
	}
}

func recoveredErr(r any) error {
	return &panicError{v: r}
}

type panicError struct{ v any }

func (e *panicError) Error() string { return "panic during collection: " + toString(e.v) }

func toString(v any) string {
	if err, ok := v.(error); ok {
		return err.Error()
	}
	if s, ok := v.(string); ok {
		return s
	}
	return "unknown panic"
}
