package devicectx

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"sentinelgo/internal/epm"
)

// withFakeCollectors substitutes the package-level collector seams for the
// duration of a test and restores the originals on cleanup — the same
// package-level function-var pattern used throughout internal/epm (e.g.
// launcher_iface_windows.go's computeFileHashFn).
func withFakeCollectors(t *testing.T, posture func() postureResult, network func(epm.Defaults) networkResult, join func() joinResult) {
	t.Helper()
	origPosture, origNetwork, origJoin := postureCollectorFn, networkCollectorFn, joinCollectorFn
	t.Cleanup(func() {
		postureCollectorFn, networkCollectorFn, joinCollectorFn = origPosture, origNetwork, origJoin
	})
	if posture != nil {
		postureCollectorFn = posture
	}
	if network != nil {
		networkCollectorFn = network
	}
	if join != nil {
		joinCollectorFn = join
	}
}

func TestNew_DefaultSnapshotIsZeroValue(t *testing.T) {
	p := New()
	snap := p.Snapshot()
	if !snap.CollectedAt.IsZero() {
		t.Errorf("CollectedAt = %v, want zero", snap.CollectedAt)
	}
	if snap.DiskEncryption != "" || snap.NetworkType != "" {
		t.Errorf("expected zero-value snapshot, got %+v", snap)
	}
	if len(snap.Sources) != 0 {
		t.Errorf("Sources = %v, want empty", snap.Sources)
	}
}

func TestProvider_CollectPosture_Success(t *testing.T) {
	withFakeCollectors(t, func() postureResult {
		return postureResult{
			diskEncryption: "encrypted", secureBoot: "enabled", firewallState: "enabled",
			antivirusHealth: "healthy", compliance: "good", tpmStatus: "enabled", osVersion: "1.2.3",
		}
	}, nil, func() joinResult {
		return joinResult{ok: true, domainJoined: epm.TriTrue, domainName: "corp.example.com", entraJoined: epm.TriFalse}
	})

	p := New()
	p.collectPosture(context.Background())

	snap := p.Snapshot()
	if snap.DiskEncryption != "encrypted" || snap.SecureBoot != "enabled" || snap.FirewallState != "enabled" ||
		snap.AntivirusHealth != "healthy" || snap.Compliance != "good" || snap.TPMStatus != "enabled" || snap.OSVersion != "1.2.3" {
		t.Errorf("posture fields not applied: %+v", snap)
	}
	if snap.DomainJoined != epm.TriTrue || snap.DomainName != "corp.example.com" || snap.EntraJoined != epm.TriFalse {
		t.Errorf("join fields not applied: %+v", snap)
	}
	if state, ok := snap.Sources["posture"]; !ok || !state.OK {
		t.Errorf(`Sources["posture"] = %+v, want OK=true`, state)
	}
	if state, ok := snap.Sources["join"]; !ok || !state.OK {
		t.Errorf(`Sources["join"] = %+v, want OK=true`, state)
	}
}

func TestProvider_CollectPosture_ErrorMarksSourceFailed(t *testing.T) {
	withFakeCollectors(t, func() postureResult {
		return postureResult{err: errors.New("boom")}
	}, nil, func() joinResult {
		t.Fatal("join collector must not run when posture collection fails")
		return joinResult{}
	})

	p := New()
	p.collectPosture(context.Background())

	snap := p.Snapshot()
	state, ok := snap.Sources["posture"]
	if !ok || state.OK || state.Err != "boom" {
		t.Errorf(`Sources["posture"] = %+v, want OK=false Err="boom"`, state)
	}
	if snap.DiskEncryption != "" {
		t.Errorf("DiskEncryption = %q, want empty (fields must not be applied on error)", snap.DiskEncryption)
	}
}

func TestProvider_CollectPosture_PanicIsRecovered(t *testing.T) {
	withFakeCollectors(t, func() postureResult {
		panic("collector exploded")
	}, nil, nil)

	p := New()
	p.collectPosture(context.Background()) // must not panic the test

	state, ok := p.Snapshot().Sources["posture"]
	if !ok || state.OK {
		t.Errorf(`Sources["posture"] = %+v, want OK=false`, state)
	}
}

func TestProvider_CollectPosture_ContextCanceled_NoUpdate(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	withFakeCollectors(t, func() postureResult {
		<-release // block until the test releases us, well after collectPosture has returned
		return postureResult{diskEncryption: "encrypted"}
	}, nil, nil)

	p := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.collectPosture(ctx)

	if _, ok := p.Snapshot().Sources["posture"]; ok {
		t.Errorf(`Sources["posture"] present after context-canceled collectPosture, want absent`)
	}
}

func TestProvider_CollectNetwork_Success(t *testing.T) {
	var gotDefaults epm.Defaults
	withFakeCollectors(t, nil, func(d epm.Defaults) networkResult {
		gotDefaults = d
		return networkResult{
			networkType: "wired", ssid: "", vpnActive: epm.TriFalse, corporateNetwork: epm.TriTrue,
			dnsSuffixes: []string{"corp.example.com"}, gateways: []string{"10.0.0.1"},
		}
	}, nil)

	p := New(WithDefaults(epm.Defaults{Org: "Acme"}))
	p.collectNetwork(context.Background())

	if gotDefaults.Org != "Acme" {
		t.Errorf("collector received defaults %+v, want Org=Acme", gotDefaults)
	}
	snap := p.Snapshot()
	if snap.NetworkType != "wired" || snap.CorporateNetwork != epm.TriTrue || snap.VPNActive != epm.TriFalse {
		t.Errorf("network fields not applied: %+v", snap)
	}
	if len(snap.DNSSuffixes) != 1 || snap.DNSSuffixes[0] != "corp.example.com" {
		t.Errorf("DNSSuffixes = %v", snap.DNSSuffixes)
	}
	if state, ok := snap.Sources["network"]; !ok || !state.OK {
		t.Errorf(`Sources["network"] = %+v, want OK=true`, state)
	}
}

func TestProvider_CollectNetwork_ErrorMarksSourceFailed(t *testing.T) {
	withFakeCollectors(t, nil, func(epm.Defaults) networkResult {
		return networkResult{err: errors.New("no interfaces")}
	}, nil)

	p := New()
	p.collectNetwork(context.Background())

	state, ok := p.Snapshot().Sources["network"]
	if !ok || state.OK || state.Err != "no interfaces" {
		t.Errorf(`Sources["network"] = %+v, want OK=false Err="no interfaces"`, state)
	}
}

func TestProvider_Start_ColdStartRunsNetworkSynchronously(t *testing.T) {
	withFakeCollectors(t, func() postureResult {
		return postureResult{diskEncryption: "encrypted"}
	}, func(epm.Defaults) networkResult {
		return networkResult{networkType: "wired"}
	}, func() joinResult {
		return joinResult{ok: true}
	})

	p := New()
	p.Start(context.Background())
	defer p.Stop()

	// Start's cold-start pass only covers the network tier; by the time
	// Start returns, NetworkType must already be populated with no polling
	// or sleep required.
	if got := p.Snapshot().NetworkType; got != "wired" {
		t.Errorf("NetworkType immediately after Start() = %q, want %q", got, "wired")
	}
}

func TestProvider_Loop_RunsOnCadence(t *testing.T) {
	var postureCalls, networkCalls int32
	withFakeCollectors(t, func() postureResult {
		atomic.AddInt32(&postureCalls, 1)
		return postureResult{diskEncryption: "encrypted"}
	}, func(epm.Defaults) networkResult {
		atomic.AddInt32(&networkCalls, 1)
		return networkResult{networkType: "wired"}
	}, func() joinResult {
		return joinResult{ok: true}
	})

	p := New(WithSlowInterval(10*time.Millisecond), WithNetworkInterval(10*time.Millisecond))
	p.Start(context.Background())
	defer p.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&postureCalls) >= 2 && atomic.LoadInt32(&networkCalls) >= 2 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for repeated collection: postureCalls=%d networkCalls=%d",
		atomic.LoadInt32(&postureCalls), atomic.LoadInt32(&networkCalls))
}

func TestProvider_Stop_WithoutStart_NoPanic(t *testing.T) {
	p := New()
	p.Stop() // must be a no-op, not block or panic
}

// TestProvider_Stop_StopsLoop asserts the guarantee Stop() can actually make:
// once it returns, Snapshot() never changes again. It deliberately does NOT
// assert that the underlying collector *function* has stopped running —
// postureCollectorFn/networkCollectorFn wrap real, synchronous OS calls with
// no cancellation hook of their own (see collectPosture/collectNetwork's
// select against ctx.Done()), so a call already in flight when Stop() races
// with a ticker cannot be force-killed, only ignored: its result lands in a
// buffered, never-drained channel and is discarded, never reaching
// p.update. That discarding is exactly what makes Snapshot() stability the
// right (and only achievable) thing to test here.
func TestProvider_Stop_StopsLoop(t *testing.T) {
	withFakeCollectors(t, func() postureResult {
		return postureResult{diskEncryption: "encrypted"}
	}, func(epm.Defaults) networkResult {
		return networkResult{networkType: "wired"}
	}, func() joinResult {
		return joinResult{ok: true}
	})

	p := New(WithSlowInterval(5 * time.Millisecond))
	p.Start(context.Background())
	p.Stop()

	after := p.Snapshot()
	time.Sleep(50 * time.Millisecond)
	if got := p.Snapshot(); got.CollectedAt != after.CollectedAt {
		t.Errorf("Snapshot() changed after Stop(): CollectedAt went from %v to %v", after.CollectedAt, got.CollectedAt)
	}
}
