// Package supabase is the agent's single client for Supabase's REST APIs:
// PostgREST RPCs (/rest/v1/rpc), Storage downloads (/storage/v1), GoTrue token
// refresh (/auth/v1) and edge functions (/functions/v1).
//
// It replaces the community Go SDKs, which have no context support, never
// check the HTTP status (postgrest-go) or buffer whole downloads in memory
// (storage-go). Every operation here takes a context, uses a shared pooled
// transport, checks the status and returns a typed *APIError on failure.
//
// The client never retries and never refreshes tokens: retry policy and 401
// recovery stay at the call sites (auth.Service.DoWithAuthRetry). It must not
// import internal/service/auth, which depends on it.
package supabase

import (
	"net/http"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/httpx"
)

// Shared transports. httpx.NewClient builds a new connection pool per call,
// so building one per request would defeat keep-alive; these are created once.
var (
	// apiHTTP serves small JSON requests (RPC, token refresh).
	apiHTTP = httpx.NewClient(30 * time.Second)
	// dlHTTP serves Storage downloads (agent binaries are 18 MB+) and edge
	// functions, whose callers bound each call with their own context deadline.
	dlHTTP = httpx.NewClient(10 * time.Minute)
)

// maxResponseBytes caps how much of a JSON response body is read into memory.
const maxResponseBytes = 16 << 20

// Client talks to one Supabase project.
type Client struct {
	baseURL string
	anonKey string
	token   func() string
	api     *http.Client
	dl      *http.Client
}

// Option customises a Client.
type Option func(*Client)

// WithHTTPClient makes the client use hc for every request (tests point it at
// an httptest server's client).
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		c.api = hc
		c.dl = hc
	}
}

// New returns a client for the project at baseURL. anonKey is sent as the
// apikey header on every request. token returns the current access token and
// is called per request, so a refreshed token is picked up immediately; it may
// be nil for clients that only call unauthenticated endpoints.
//
// baseURL is used verbatim (no trailing-slash normalisation) so request URLs
// stay byte-identical to the ones the agent has always built.
func New(baseURL, anonKey string, token func() string, opts ...Option) *Client {
	c := &Client{
		baseURL: baseURL,
		anonKey: anonKey,
		token:   token,
		api:     apiHTTP,
		dl:      dlHTTP,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// FromConfig returns a client for cfg's project that reads the access token
// through cfg.GetAccessToken on every request.
func FromConfig(cfg *config.Config, opts ...Option) *Client {
	return New(cfg.SupabaseURL, cfg.SupabaseKey, cfg.GetAccessToken, opts...)
}

// setCommonHeaders sets the headers every Supabase request carries. When
// bearer is true and a token is available, it is sent as Authorization.
func (c *Client) setCommonHeaders(req *http.Request, bearer bool) {
	req.Header.Set("apikey", c.anonKey)
	req.Header.Set("X-Client-Info", "sentinelgo/"+config.Version)
	if bearer && c.token != nil {
		if tok := c.token(); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}
}
