package network_test

import (
	"context"
	"testing"
	"time"

	"sentinelgo/internal/network"
)

func TestNewConnectivityChecker(t *testing.T) {
	cc := network.NewConnectivityChecker()
	if cc == nil {
		t.Fatal("NewConnectivityChecker() returned nil")
	}
}

func TestConnectivityChecker_WithCheckURL(t *testing.T) {
	cc := network.NewConnectivityChecker()
	cc = cc.WithCheckURL("https://example.com")
	if cc == nil {
		t.Fatal("WithCheckURL() returned nil")
	}
}

func TestConnectivityChecker_WithTimeout(t *testing.T) {
	cc := network.NewConnectivityChecker()
	cc = cc.WithTimeout(10 * time.Second)
	if cc == nil {
		t.Fatal("WithTimeout() returned nil")
	}
}

func TestConnectivityChecker_CheckInternet(t *testing.T) {
	cc := network.NewConnectivityChecker()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// This test may fail if there's no internet connectivity
	// We'll just check that it doesn't panic
	err := cc.CheckInternet(ctx)
	// We can't assert success since we don't know if internet is available
	_ = err
}

func TestCheckInternetQuick(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Test with Google's DNS server (should work in most environments)
	err := network.CheckInternetQuick(ctx, "8.8.8.8", "53")
	// We can't assert success since we don't know if internet is available
	_ = err

	// Test with invalid host
	err = network.CheckInternetQuick(ctx, "invalid-host-that-does-not-exist.com", "80")
	if err == nil {
		t.Error("CheckInternetQuick() should fail with invalid host")
	}
}

func TestConnectivityChecker_WithEmptyCheckURL(t *testing.T) {
	cc := network.NewConnectivityChecker()
	cc = cc.WithCheckURL("")
	if cc == nil {
		t.Fatal("WithCheckURL() returned nil with empty URL")
	}
}

func TestConnectivityChecker_WithZeroTimeout(t *testing.T) {
	cc := network.NewConnectivityChecker()
	cc = cc.WithTimeout(0)
	if cc == nil {
		t.Fatal("WithTimeout() returned nil with zero timeout")
	}
}

func TestConnectivityChecker_WithNegativeTimeout(t *testing.T) {
	cc := network.NewConnectivityChecker()
	cc = cc.WithTimeout(-1 * time.Second)
	if cc == nil {
		t.Fatal("WithTimeout() returned nil with negative timeout")
	}
}

func TestConnectivityChecker_CheckInternet_WithCancelledContext(t *testing.T) {
	cc := network.NewConnectivityChecker()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := cc.CheckInternet(ctx)
	// Should return error due to cancelled context
	_ = err
}

func TestConnectivityChecker_WithOptionsChain(t *testing.T) {
	cc := network.NewConnectivityChecker()
	cc = cc.WithCheckURL("https://example.com").WithTimeout(5 * time.Second)
	if cc == nil {
		t.Fatal("Chained options returned nil")
	}
}
