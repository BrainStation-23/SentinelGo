//go:build windows

package epm

import (
	"context"
	"testing"
	"time"
)

// TestPipeServer_StopBeforeCancelDoesNotDeadlock is the regression test for a
// real deadlock this package shipped briefly during Phase 2's transport
// de-duplication: Server.Serve's accept loop retries on any Accept error
// whose ctx is not yet Done, and Stop()/Close() is not guaranteed to run
// after ctx has already been cancelled — this exact cleanup order (Stop()
// then cancel()) is what pipe_integration_windows_test.go's
// startTestPipeServer already used. A CancelIoEx aimed at only the single
// currently-blocked pipe instance can lose the race against a retry that
// creates a brand new instance and blocks on IT instead, with nothing left
// to cancel it — hanging Serve forever. It reproduced under `go test ./...`
// (different goroutine scheduling than an isolated run) but not reliably in
// isolation, which is why this test repeats the start/stop cycle many times:
// a single pass is not a strong enough guarantee against a timing-dependent
// race.
//
// See windowsTransport's closed field (transport_windows.go) for the fix:
// Accept checks it before ever creating a new pipe instance, so once Close
// has run, no further instance is ever created to block on.
func TestPipeServer_StopBeforeCancelDoesNotDeadlock(t *testing.T) {
	const iterations = 50
	for i := 0; i < iterations; i++ {
		server := NewPipeServer(staticRuleProvider{}, nil)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- server.Serve(ctx) }()

		// Give Serve a moment to actually reach ConnectNamedPipe before
		// stopping it — stopping before the first instance is even created
		// would not exercise the race this test targets.
		time.Sleep(2 * time.Millisecond)

		// The exact order that triggered the deadlock: Stop() before cancel().
		server.Stop()
		cancel()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: Serve did not return within 5s of Stop()+cancel() — deadlocked", i)
		}
	}
}
