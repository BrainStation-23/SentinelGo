package network

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ── CheckInternet ────────────────────────────────────────────────────────────

func TestCheckInternet_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewConnectivityChecker().WithCheckURL(srv.URL)
	if err := c.CheckInternet(context.Background()); err != nil {
		t.Fatalf("CheckInternet: %v", err)
	}
}

func TestCheckInternet_AnyHTTPStatusIsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewConnectivityChecker().WithCheckURL(srv.URL)
	if err := c.CheckInternet(context.Background()); err != nil {
		t.Errorf("CheckInternet should treat any HTTP response (even 5xx) as reachable, got err: %v", err)
	}
}

func TestCheckInternet_UnreachableURLFails(t *testing.T) {
	c := NewConnectivityChecker().
		WithCheckURL("http://127.0.0.1:1"). // reserved port, connection refused
		WithTimeout(500 * time.Millisecond)

	if err := c.CheckInternet(context.Background()); err == nil {
		t.Fatal("expected an error for an unreachable check URL")
	}
}

func TestCheckInternet_InvalidURLFails(t *testing.T) {
	c := NewConnectivityChecker().WithCheckURL("://not-a-valid-url")
	if err := c.CheckInternet(context.Background()); err == nil {
		t.Fatal("expected an error for a malformed check URL")
	}
}

func TestWithTimeout_AppliesToHTTPClient(t *testing.T) {
	c := NewConnectivityChecker().WithTimeout(2 * time.Second)
	if c.httpClient.Timeout != 2*time.Second {
		t.Errorf("httpClient.Timeout = %v, want 2s", c.httpClient.Timeout)
	}
	if c.timeout != 2*time.Second {
		t.Errorf("timeout = %v, want 2s", c.timeout)
	}
}

// ── CheckInternetQuick ───────────────────────────────────────────────────────

func TestCheckInternetQuick_Success(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}

	if err := CheckInternetQuick(context.Background(), host, port); err != nil {
		t.Fatalf("CheckInternetQuick: %v", err)
	}
}

func TestCheckInternetQuick_ConnectionRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	if err := CheckInternetQuick(ctx, "127.0.0.1", "1"); err == nil {
		t.Fatal("expected an error for a refused TCP connection")
	}
}

func TestCheckInternetQuick_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := CheckInternetQuick(ctx, "127.0.0.1", "80"); err == nil {
		t.Fatal("expected an error when context is already cancelled")
	}
}
