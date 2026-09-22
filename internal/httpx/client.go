// Package httpx provides shared HTTP client construction for the agent.
//
// Centralizing client creation gives every caller the same connection-pool
// tuning, which matters for a long-running service: idle connections are
// reused across heartbeats, polls, and uploads instead of being reopened on
// every request.
package httpx

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// NewClient returns an *http.Client with the given request timeout and a
// connection pool suited to a long-lived agent process. Pass the timeout that
// matches the call site (e.g. a short timeout for health checks, a longer one
// for script execution or downloads).
func NewClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		// Floor the negotiated version. Go's own default is already TLS 1.2 for
		// clients, but stating it here means a future Go release cannot quietly
		// lower it, and it documents that every agent call is expected to be
		// TLS-protected (config validation rejects non-loopback http:// URLs).
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}
