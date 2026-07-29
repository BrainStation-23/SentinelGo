package transportbe

import (
	"context"
	"errors"
	"testing"

	"sentinelgo/internal/epm"
)

// fakePolicyTransport is a minimal PolicyTransport stub for negotiation
// tests — only Probe/Name matter here, Fetch/Ack are never exercised by
// Negotiator itself.
type fakePolicyTransport struct {
	name     string
	probeErr func() error // called fresh each Probe, so a test can vary the result per call
}

func (f *fakePolicyTransport) Name() string { return f.name }
func (f *fakePolicyTransport) Probe(context.Context) error {
	if f.probeErr == nil {
		return nil
	}
	return f.probeErr()
}
func (f *fakePolicyTransport) Fetch(context.Context, PolicyCursor) (*epm.SignedBundle, error) {
	return nil, nil
}
func (f *fakePolicyTransport) Ack(context.Context, string, bool, string) error { return nil }

func TestNegotiator_V2Success_SelectsV2(t *testing.T) {
	v1 := Transports{Policy: &fakePolicyTransport{name: "v1-piggyback"}}
	v2 := Transports{Policy: &fakePolicyTransport{name: "v2-rpc"}}

	n := NewNegotiator("auto", v1, v2)
	got := n.Select(context.Background())
	if got.Policy.Name() != "v2-rpc" {
		t.Errorf("Select() = %q, want v2-rpc", got.Policy.Name())
	}
}

func TestNegotiator_404_LatchesToV1Immediately(t *testing.T) {
	v1 := Transports{Policy: &fakePolicyTransport{name: "v1-piggyback"}}
	v2 := Transports{Policy: &fakePolicyTransport{name: "v2-rpc", probeErr: func() error {
		return &StatusError{Status: 404, Err: errors.New("not found")}
	}}}

	n := NewNegotiator("auto", v1, v2)
	got := n.Select(context.Background())
	if got.Policy.Name() != "v1-piggyback" {
		t.Fatalf("Select() = %q, want v1-piggyback", got.Policy.Name())
	}
	if !n.latchedV1 {
		t.Error("latchedV1 = false, want true after a single 404")
	}

	// A subsequent call must stay latched even if v2 would now succeed.
	v2.Policy.(*fakePolicyTransport).probeErr = nil
	got = n.Select(context.Background())
	if got.Policy.Name() != "v1-piggyback" {
		t.Errorf("Select() after latch = %q, want v1-piggyback (latch must not clear itself)", got.Policy.Name())
	}
}

func TestNegotiator_501_LatchesToV1Immediately(t *testing.T) {
	v1 := Transports{Policy: &fakePolicyTransport{name: "v1-piggyback"}}
	v2 := Transports{Policy: &fakePolicyTransport{name: "v2-rpc", probeErr: func() error {
		return &StatusError{Status: 501, Err: errors.New("not implemented")}
	}}}

	n := NewNegotiator("auto", v1, v2)
	got := n.Select(context.Background())
	if got.Policy.Name() != "v1-piggyback" {
		t.Errorf("Select() = %q, want v1-piggyback", got.Policy.Name())
	}
}

func TestNegotiator_RepeatedFiveHundreds_TripsBreakerAndLatches(t *testing.T) {
	v1 := Transports{Policy: &fakePolicyTransport{name: "v1-piggyback"}}
	v2 := Transports{Policy: &fakePolicyTransport{name: "v2-rpc", probeErr: func() error {
		return &StatusError{Status: 500, Err: errors.New("server error")}
	}}}

	n := NewNegotiator("auto", v1, v2)

	// The circuit breaker is constructed with maxFailures=5 (matching the
	// plan's literal resilience.NewCircuitBreaker("epm-transport-v2", 5, ...)
	// call) — the first 4 failures must NOT latch, only the 5th.
	var last Transports
	for i := 0; i < 5; i++ {
		last = n.Select(context.Background())
	}
	if last.Policy.Name() != "v1-piggyback" {
		t.Fatalf("Select() after 5 consecutive 5xx = %q, want v1-piggyback", last.Policy.Name())
	}
	if !n.latchedV1 {
		t.Error("latchedV1 = false, want true after the breaker trips")
	}
}

func TestNegotiator_TransientFailureDoesNotLatch(t *testing.T) {
	v1 := Transports{Policy: &fakePolicyTransport{name: "v1-piggyback"}}
	calls := 0
	v2 := Transports{Policy: &fakePolicyTransport{name: "v2-rpc", probeErr: func() error {
		calls++
		if calls == 1 {
			return &StatusError{Status: 500, Err: errors.New("blip")}
		}
		return nil // recovers on the second probe
	}}}

	n := NewNegotiator("auto", v1, v2)

	first := n.Select(context.Background())
	if first.Policy.Name() != "v1-piggyback" {
		t.Errorf("Select() after 1st failure = %q, want v1-piggyback (single blip, not latched)", first.Policy.Name())
	}
	if n.latchedV1 {
		t.Error("latchedV1 = true after a single transient failure, want false")
	}

	second := n.Select(context.Background())
	if second.Policy.Name() != "v2-rpc" {
		t.Errorf("Select() after recovery = %q, want v2-rpc", second.Policy.Name())
	}
}

func TestNegotiator_SuccessIsCachedForTTL(t *testing.T) {
	v1 := Transports{Policy: &fakePolicyTransport{name: "v1-piggyback"}}
	calls := 0
	v2 := Transports{Policy: &fakePolicyTransport{name: "v2-rpc", probeErr: func() error {
		calls++
		return nil
	}}}

	n := NewNegotiator("auto", v1, v2)
	n.Select(context.Background())
	n.Select(context.Background())
	n.Select(context.Background())

	if calls != 1 {
		t.Errorf("v2 was probed %d times, want 1 (subsequent calls should use the cached success)", calls)
	}
}

func TestNegotiator_PinnedV1_NeverProbes(t *testing.T) {
	probed := false
	v1 := Transports{Policy: &fakePolicyTransport{name: "v1-piggyback"}}
	v2 := Transports{Policy: &fakePolicyTransport{name: "v2-rpc", probeErr: func() error {
		probed = true
		return nil
	}}}

	n := NewNegotiator("v1", v1, v2)
	got := n.Select(context.Background())
	if got.Policy.Name() != "v1-piggyback" {
		t.Errorf("Select() = %q, want v1-piggyback", got.Policy.Name())
	}
	if probed {
		t.Error("a pinned v1 mode must never probe v2")
	}
}

func TestNegotiator_PinnedV2_NeverFallsBackEvenOnFailure(t *testing.T) {
	v1 := Transports{Policy: &fakePolicyTransport{name: "v1-piggyback"}}
	v2 := Transports{Policy: &fakePolicyTransport{name: "v2-rpc", probeErr: func() error {
		return errors.New("v2 is actually down")
	}}}

	n := NewNegotiator("v2", v1, v2)
	got := n.Select(context.Background())
	if got.Policy.Name() != "v2-rpc" {
		t.Errorf("Select() = %q, want v2-rpc (pinned mode trusts the operator, never probes/falls back)", got.Policy.Name())
	}
}
