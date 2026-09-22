package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"syscall"
	"testing"
)

// timeoutErr is a net.Error that reports a timeout without being a *net.OpError,
// standing in for the shapes an HTTP client surfaces when a response never
// arrives.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// TestIsRefreshTokenUnused guards the rule that a refresh token is only ever
// re-sent when the failure proves it was never delivered.
//
// Supabase rotates the refresh token on every successful exchange. If the
// request reached the server and the response was lost, the token we still hold
// is already spent -- re-sending it cannot succeed, and under GoTrue
// refresh-token reuse detection it is read as a replay and revokes the whole
// session family. So "transient" is the wrong question; "did a connection ever
// come up" is the right one.
func TestIsRefreshTokenUnused(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
		why  string
	}{
		{
			name: "nil",
			err:  nil,
			want: false,
		},
		{
			name: "dns failure",
			err:  &net.DNSError{Err: "no such host", Name: "db.example.com"},
			want: true,
			why:  "resolution fails before a connection exists",
		},
		{
			name: "dns timeout",
			err:  &net.DNSError{Err: "timeout", Name: "db.example.com", IsTimeout: true},
			want: true,
			why:  "still resolution: nothing was sent",
		},
		{
			name: "dial refused",
			err:  &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED},
			want: true,
			why:  "no TCP connection, so no request was written",
		},
		{
			name: "dial timeout",
			err:  &net.OpError{Op: "dial", Net: "tcp", Err: timeoutErr{}},
			want: true,
			why:  "a dial timeout is still a dial failure",
		},
		{
			name: "read reset",
			err:  &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET},
			want: false,
			why:  "connection was up: the request may have been delivered",
		},
		{
			name: "write reset",
			err:  &net.OpError{Op: "write", Net: "tcp", Err: syscall.ECONNRESET},
			want: false,
			why:  "a partial write may still have been processed",
		},
		{
			name: "response timeout",
			err:  timeoutErr{},
			want: false,
			why:  "the timeout may have fired after the request went out",
		},
		{
			name: "context deadline",
			err:  context.DeadlineExceeded,
			want: false,
			why:  "says nothing about how far the request got",
		},
		{
			name: "context canceled",
			err:  context.Canceled,
			want: false,
		},
		{
			name: "unexpected EOF",
			err:  io.ErrUnexpectedEOF,
			want: false,
			why:  "server may have processed the request before dropping",
		},
		{
			name: "opaque error",
			err:  errors.New("something went wrong"),
			want: false,
			why:  "unknown means unsafe",
		},
		{
			name: "server rejected the token",
			err:  errors.New("response status code 400: invalid_grant"),
			want: false,
			why:  "the server saw it; retrying replays a spent token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRefreshTokenUnused(tt.err); got != tt.want {
				t.Errorf("isRefreshTokenUnused(%v) = %v, want %v (%s)",
					tt.err, got, tt.want, tt.why)
			}
		})
	}
}

// TestIsRefreshTokenUnused_ThroughWrappers checks the classification survives the
// layers between us and the socket. net/http returns *url.Error, and the Supabase
// SDKs add their own wrapping on top.
func TestIsRefreshTokenUnused_ThroughWrappers(t *testing.T) {
	dial := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	read := &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "url.Error around dial",
			err:  &url.Error{Op: "Post", URL: "https://db.example.com", Err: dial},
			want: true,
		},
		{
			name: "url.Error around read",
			err:  &url.Error{Op: "Post", URL: "https://db.example.com", Err: read},
			want: false,
		},
		{
			name: "fmt-wrapped url.Error around dial",
			err: fmt.Errorf("refresh session: %w",
				&url.Error{Op: "Post", URL: "https://db.example.com", Err: dial}),
			want: true,
		},
		{
			name: "flattened chain falls back to no-retry",
			// An SDK that formats with %v instead of %w destroys the chain.
			// Losing the detail must fail safe, not fail open.
			err:  fmt.Errorf("refresh session: %v", dial),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRefreshTokenUnused(tt.err); got != tt.want {
				t.Errorf("isRefreshTokenUnused(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
