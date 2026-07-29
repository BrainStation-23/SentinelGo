package transportbe

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"sentinelgo/internal/resilience"
)

// probeCacheTTL is how long a successful v2 probe is trusted before
// Negotiator probes again — matches the plan's "cache success for 1 h".
const probeCacheTTL = 1 * time.Hour

// Transports bundles the PolicyTransport and EventTransport that always
// come from the same backend version — a caller never wants policy from v2
// and events from v1 mid-run.
type Transports struct {
	Policy PolicyTransport
	Event  EventTransport
}

// Negotiator selects between a v1 and v2 Transports pair. In auto mode
// (the default) it probes v2 once, caches a successful probe for
// probeCacheTTL, and latches to v1 for the remainder of the process's run
// on a 404/501 (the endpoint plainly does not exist — no point retrying)
// or once resilience.CircuitBreaker("epm-transport-v2", 5, 5*time.Minute)
// opens from repeated 5xx/network failures — the exact construction the
// plan specifies. The latch is permanent for the run, the same one-way
// design as enforce's kill-rate limiter: a backend that could not serve v2
// once this run is not worth re-probing every cycle.
type Negotiator struct {
	mode string
	v1   Transports
	v2   Transports

	breaker *resilience.CircuitBreaker
	now     func() time.Time

	mu          sync.Mutex
	latchedV1   bool
	latchLogged bool
	lastProbeOK time.Time
}

// NewNegotiator builds a Negotiator. mode is normally
// config.Config.GetEPMBackendTransport()'s value
// (EPMBackendTransportAuto/V1/V2).
func NewNegotiator(mode string, v1, v2 Transports) *Negotiator {
	return &Negotiator{
		mode:    mode,
		v1:      v1,
		v2:      v2,
		breaker: resilience.NewCircuitBreaker("epm-transport-v2", 5, 5*time.Minute),
		now:     time.Now,
	}
}

// Select returns the transport pair to use right now, probing and latching
// as described in the Negotiator doc comment when mode is auto. v1/v2 pins
// bypass all of that and always return the requested pair, even if it has
// never been probed — an operator who pins a transport is asserting it
// works, not asking to be second-guessed.
func (n *Negotiator) Select(ctx context.Context) Transports {
	switch n.mode {
	case "v1":
		return n.v1
	case "v2":
		return n.v2
	default:
		return n.selectAuto(ctx)
	}
}

func (n *Negotiator) selectAuto(ctx context.Context) Transports {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.latchedV1 {
		return n.v1
	}
	if !n.lastProbeOK.IsZero() && n.now().Sub(n.lastProbeOK) < probeCacheTTL {
		return n.v2
	}

	err := n.breaker.Execute(ctx, func() error { return n.v2.Policy.Probe(ctx) })
	if err == nil {
		n.lastProbeOK = n.now()
		return n.v2
	}

	var statusErr *StatusError
	permanentFailure := errors.As(err, &statusErr) && (statusErr.Status == 404 || statusErr.Status == 501)
	breakerOpen := n.breaker.GetState() == resilience.StateOpen

	if permanentFailure || breakerOpen {
		n.latchedV1 = true
		if !n.latchLogged {
			n.latchLogged = true
			log.Printf("epm: transportbe: v2 unreachable (%v), latching to v1-piggyback for the remainder of this run", err)
		}
		return n.v1
	}

	// Transient failure, breaker still closed: use v1 for this call, but
	// leave lastProbeOK/latchedV1 untouched so the next Select tries v2
	// again rather than latching prematurely on a single blip.
	return n.v1
}
