package rpcutil

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCallWithTimeout_Fast(t *testing.T) {
	got, err := CallWithTimeout(context.Background(), time.Second, func() (string, error) {
		return "ok", nil
	})
	if err != nil || got != "ok" {
		t.Fatalf("got (%q, %v), want (\"ok\", nil)", got, err)
	}
}

func TestCallWithTimeout_PropagatesError(t *testing.T) {
	sentinel := errors.New("boom")
	_, err := CallWithTimeout(context.Background(), time.Second, func() (string, error) {
		return "", sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want wrapping %v", err, sentinel)
	}
}

func TestCallWithTimeout_TimesOut(t *testing.T) {
	start := time.Now()
	_, err := CallWithTimeout(context.Background(), 50*time.Millisecond, func() (string, error) {
		time.Sleep(2 * time.Second) // simulates a hung RPC
		return "late", nil
	})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("CallWithTimeout blocked %s, should have returned at ~50ms", elapsed)
	}
}
