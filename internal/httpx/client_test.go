package httpx_test

import (
	"net/http"
	"testing"
	"time"

	"sentinelgo/internal/httpx"
)

func TestNewClient_ReturnsNonNil(t *testing.T) {
	c := httpx.NewClient(30 * time.Second)
	if c == nil {
		t.Fatal("NewClient returned nil")
	}
}

func TestNewClient_TimeoutIsSet(t *testing.T) {
	timeout := 45 * time.Second
	c := httpx.NewClient(timeout)
	if c.Timeout != timeout {
		t.Errorf("Timeout: got %v, want %v", c.Timeout, timeout)
	}
}

func TestNewClient_ZeroTimeout(t *testing.T) {
	c := httpx.NewClient(0)
	if c == nil {
		t.Fatal("NewClient(0) returned nil")
		return // Early return to satisfy staticcheck
	}
	if c.Timeout != 0 {
		t.Errorf("Timeout with zero: got %v, want 0", c.Timeout)
	}
}

func TestNewClient_HasCustomTransport(t *testing.T) {
	c := httpx.NewClient(10 * time.Second)
	if c.Transport == nil {
		t.Fatal("expected a custom Transport, got nil (would use default which lacks pool tuning)")
	}
}

func TestNewClient_TransportIsHTTPTransport(t *testing.T) {
	c := httpx.NewClient(10 * time.Second)
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", c.Transport)
	}
	if tr.MaxIdleConns == 0 {
		t.Error("MaxIdleConns should be non-zero for connection reuse")
	}
	if tr.MaxIdleConnsPerHost == 0 {
		t.Error("MaxIdleConnsPerHost should be non-zero for connection reuse")
	}
	if tr.IdleConnTimeout == 0 {
		t.Error("IdleConnTimeout should be non-zero")
	}
}

func TestNewClient_DifferentTimeouts_IndependentClients(t *testing.T) {
	c1 := httpx.NewClient(10 * time.Second)
	c2 := httpx.NewClient(60 * time.Second)

	if c1.Timeout != 10*time.Second {
		t.Errorf("c1 timeout: got %v, want 10s", c1.Timeout)
	}
	if c2.Timeout != 60*time.Second {
		t.Errorf("c2 timeout: got %v, want 60s", c2.Timeout)
	}
	if c1 == c2 {
		t.Error("NewClient should return independent client instances")
	}
}
