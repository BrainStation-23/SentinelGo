package network_test

import (
	"context"
	"testing"
	"time"

	"sentinelgo/internal/network"
)

func TestConnectivityChecker_Chaining(t *testing.T) {
	cc := network.NewConnectivityChecker()

	cc = cc.WithCheckURL("https://example.com").WithTimeout(10 * time.Second)
	if cc == nil {
		t.Fatal("Chaining options returned nil")
	}
}

func TestConnectivityChecker_InvalidURL(t *testing.T) {
	cc := network.NewConnectivityChecker().WithCheckURL("invalid-url")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// This should fail due to invalid URL
	err := cc.CheckInternet(ctx)
	// Should not panic
	_ = err
}

func TestCheckInternetQuick_InvalidHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// This should fail due to invalid host
	err := network.CheckInternetQuick(ctx, "invalid-host:9999", "1s")
	// Should not panic
	_ = err
}

func TestCheckInternetQuick_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// This should timeout due to very short timeout
	err := network.CheckInternetQuick(ctx, "example.com", "1ns")
	// Should not panic
	_ = err
}

func TestConnectivityChecker_EmptyURL(t *testing.T) {
	cc := network.NewConnectivityChecker().WithCheckURL("")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Should not panic with empty URL
	err := cc.CheckInternet(ctx)
	_ = err
}

func TestConnectivityChecker_VeryShortTimeout(t *testing.T) {
	cc := network.NewConnectivityChecker().WithTimeout(1 * time.Nanosecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Should not panic with very short timeout
	err := cc.CheckInternet(ctx)
	_ = err
}
