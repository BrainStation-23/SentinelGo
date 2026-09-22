package network

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"sentinelgo/internal/httpx"
)

// ConnectivityChecker provides network connectivity checking functionality
type ConnectivityChecker struct {
	httpClient *http.Client
	checkURL   string
	timeout    time.Duration
}

// NewConnectivityChecker creates a new connectivity checker
func NewConnectivityChecker() *ConnectivityChecker {
	return &ConnectivityChecker{
		checkURL:   "https://www.google.com",
		timeout:    5 * time.Second,
		httpClient: httpx.NewClient(5 * time.Second),
	}
}

// WithCheckURL sets the URL to check connectivity against
func (c *ConnectivityChecker) WithCheckURL(url string) *ConnectivityChecker {
	c.checkURL = url
	return c
}

// WithTimeout sets the timeout for connectivity checks
func (c *ConnectivityChecker) WithTimeout(timeout time.Duration) *ConnectivityChecker {
	c.timeout = timeout
	c.httpClient.Timeout = timeout
	return c
}

// CheckInternet checks if internet connectivity is available via an HTTP HEAD request.
func (c *ConnectivityChecker) CheckInternet(ctx context.Context) error {
	checkCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	if err := c.checkHTTP(checkCtx); err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}

	return nil
}

// checkHTTP performs an HTTP HEAD request. Any response (including 5xx) means
// the network path to the server is open.
//
// Peer identity is established by the TLS layer, not here: the client comes from
// httpx (certificate verification on, TLS 1.2 floor) and config validation
// restricts supabase_url to https for non-loopback hosts, so reaching the
// response stage at all means the certificate chain validated.
func (c *ConnectivityChecker) checkHTTP(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.checkURL, nil)
	if err != nil {
		return fmt.Errorf("create HTTP request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("Connectivity: Failed to close response body: %v", closeErr)
		}
	}()

	return nil
}

// CheckInternetQuick performs a quick internet connectivity check using a TCP
// connection. The caller's context controls the deadline.
//
// This proves only that something accepted a TCP connection at that address. It
// establishes nothing about the peer's identity -- a captive portal or any
// transparent proxy satisfies it -- so it must not be used to gate a
// security-relevant action. Where a probe guards such an action, complete a
// verified TLS handshake instead; see updater.CheckInternetConnectivity.
func CheckInternetQuick(ctx context.Context, host string, port string) error {
	address := net.JoinHostPort(host, port)

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("TCP connection failed to %s: %w", address, err)
	}
	if closeErr := conn.Close(); closeErr != nil {
		log.Printf("Connectivity: Failed to close TCP connection: %v", closeErr)
	}

	return nil
}
