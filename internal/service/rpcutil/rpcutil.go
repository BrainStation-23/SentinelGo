// Package rpcutil provides shared helpers for bounding Supabase RPC calls.
package rpcutil

import (
	"context"
	"fmt"
	"time"
)

// CallWithTimeout runs fn (a blocking RPC) and returns its result, or an error
// if ctx is cancelled or timeout elapses first.
//
// The postgrest-go client has no HTTP timeout and its Rpc method ignores
// context, so a hung connection (NAT timeout, half-open TCP) would otherwise
// block the caller forever. In the scheduler that leaves the task's Running
// flag set, so every subsequent tick is skipped and reporting silently stops
// until the process restarts. Bounding the caller here guarantees the task
// returns and runs again on the next tick.
//
// The goroutine spawned to call fn lives until fn returns or panics. If the
// context is cancelled before fn completes, the goroutine remains active until
// fn finishes (or the process exits). This is acceptable: the call is in-flight
// and cannot be cancelled mid-request. The goroutine itself is cheap (a few KB)
// and the select ensures this function returns promptly despite fn still running.
func CallWithTimeout(ctx context.Context, timeout time.Duration, fn func() (string, error)) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type result struct {
		s   string
		err error
	}
	// Buffered so the goroutine never blocks on send if we have already
	// returned via the timeout branch.
	ch := make(chan result, 1)
	go func() {
		s, err := fn()
		ch <- result{s: s, err: err}
	}()

	select {
	case r := <-ch:
		return r.s, r.err
	case <-ctx.Done():
		return "", fmt.Errorf("rpc timed out after %s: %w", timeout, ctx.Err())
	}
}
