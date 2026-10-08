package supabase_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/supabase"
	"sentinelgo/internal/supabase/supabasetest"
)

func TestRPC_DecodesResponseAndSendsHeaders(t *testing.T) {
	fake := supabasetest.New(t)
	fake.Handle("POST", "/rest/v1/rpc/agent_enqueue_audit_logs", supabasetest.Response{Body: `{"success":true,"msg_id":42,"queue":"audit"}`})

	var out struct {
		Success bool   `json:"success"`
		MsgID   int64  `json:"msg_id"`
		Queue   string `json:"queue"`
	}
	err := fake.Client(nil).RPC(context.Background(), "agent_enqueue_audit_logs",
		map[string]string{"p_note": "a\x00b"}, &out, supabase.WithHeader("X-Device-ID", "dev-1"))
	if err != nil {
		t.Fatalf("RPC: %v", err)
	}
	if !out.Success || out.MsgID != 42 || out.Queue != "audit" {
		t.Errorf("decoded %+v", out)
	}
	r := fake.Requests()[0]
	if r.Header.Get("X-Device-ID") != "dev-1" {
		t.Errorf("X-Device-ID = %q", r.Header.Get("X-Device-ID"))
	}
	if r.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
	}
	if bytes.Contains(r.Body, []byte(`\u0000`)) {
		t.Errorf("NUL escape not stripped from body: %s", r.Body)
	}
}

func TestRPC_WithHeaderCannotOverrideAuth(t *testing.T) {
	fake := supabasetest.New(t)
	fake.Handle("POST", "/rest/v1/rpc/f", supabasetest.Response{Body: `null`})
	err := fake.Client(func() string { return "real" }).RPC(context.Background(), "f", nil, nil,
		supabase.WithHeader("Authorization", "Bearer spoofed"), supabase.WithHeader("apikey", "spoofed"))
	if err != nil {
		t.Fatalf("RPC: %v", err)
	}
	r := fake.Requests()[0]
	if r.Header.Get("Authorization") != "Bearer real" || r.Header.Get("apikey") != supabasetest.AnonKey {
		t.Errorf("auth headers overridden: Authorization=%q apikey=%q", r.Header.Get("Authorization"), r.Header.Get("apikey"))
	}
}

func TestRPC_ErrorStatusIsAPIError(t *testing.T) {
	fake := supabasetest.New(t)
	fake.Handle("POST", "/rest/v1/rpc/f", supabasetest.Response{Status: 500, Body: `{"code":"XX000","message":"boom"}`})

	var out map[string]any
	err := fake.Client(nil).RPC(context.Background(), "f", nil, &out)
	apiErr, ok := supabase.AsAPIError(err)
	if !ok {
		t.Fatalf("err = %v, want *APIError", err)
	}
	if apiErr.Status != 500 || apiErr.Code != "XX000" || apiErr.Path != "/rest/v1/rpc/f" {
		t.Errorf("APIError = %+v", apiErr)
	}
	if out != nil {
		t.Errorf("out was decoded from an error response: %v", out)
	}
}

func TestRPC_ExpiredJWTIsUnauthorized(t *testing.T) {
	fake := supabasetest.New(t)
	fake.Handle("POST", "/rest/v1/rpc/f", supabasetest.Response{Body: `{}`})
	fake.ExpireJWT()

	err := fake.Client(nil).RPC(context.Background(), "f", nil, nil)
	if !supabase.IsUnauthorized(err) {
		t.Fatalf("err = %v, want unauthorized", err)
	}
}

func TestRPC_ContextTimeout(t *testing.T) {
	fake := supabasetest.New(t)
	fake.Handle("POST", "/rest/v1/rpc/slow", supabasetest.Response{Body: `{}`, Delay: 5 * time.Second})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := fake.Client(nil).RPC(ctx, "slow", nil, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("RPC ignored the context deadline (took %s)", time.Since(start))
	}
	if supabase.StatusCode(err) != 0 {
		t.Errorf("StatusCode(timeout) = %d, want 0", supabase.StatusCode(err))
	}
}

func TestDownload_StreamsWithinLimit(t *testing.T) {
	fake := supabasetest.New(t)
	payload := strings.Repeat("a", 1000)
	fake.Handle("GET", "/storage/v1/object/b/f", supabasetest.Response{Body: payload})

	var buf bytes.Buffer
	n, err := fake.Client(nil).Download(context.Background(), "b", "f", false, &buf, 1000)
	if err != nil || n != 1000 || buf.String() != payload {
		t.Fatalf("Download = %d, %v (len %d)", n, err, buf.Len())
	}
}

func TestDownload_RejectsOversizedInsteadOfTruncating(t *testing.T) {
	fake := supabasetest.New(t)
	fake.Handle("GET", "/storage/v1/object/authenticated/command-scripts/big.sh",
		supabasetest.Response{Body: strings.Repeat("a", 1001)})

	var buf bytes.Buffer
	_, err := fake.Client(nil).Download(context.Background(), "command-scripts", "big.sh", true, &buf, 1000)
	if !errors.Is(err, supabase.ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if buf.Len() > 1000 {
		t.Errorf("wrote %d bytes, want at most the 1000-byte limit", buf.Len())
	}
}

func TestDownload_ErrorShapes(t *testing.T) {
	fake := supabasetest.New(t)
	fake.Handle("GET", "/storage/v1/object/agent-releases/missing",
		supabasetest.Response{Status: 400, Body: `{"statusCode":"404","error":"not_found","message":"Object not found"}`})
	c := fake.Client(nil)

	_, err := c.Download(context.Background(), "agent-releases", "missing", false, &bytes.Buffer{}, 0)
	if !supabase.IsNotFound(err) {
		t.Errorf("missing object: err = %v, want not found", err)
	}

	fake.Handle("GET", "/storage/v1/object/agent-releases/present", supabasetest.Response{Body: "x"})
	fake.ExpireJWT()
	_, err = c.Download(context.Background(), "agent-releases", "present", false, &bytes.Buffer{}, 0)
	if !supabase.IsUnauthorized(err) {
		t.Errorf("expired JWT: err = %v, want unauthorized", err)
	}
}

func TestRefreshSession_Rotation(t *testing.T) {
	fake := supabasetest.New(t)
	fake.RotateRefresh()
	c := fake.Client(nil)
	ctx := context.Background()

	s, err := c.RefreshSession(ctx, "refresh-0")
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if s.AccessToken != "access-1" || s.RefreshToken != "refresh-1" {
		t.Errorf("session = %+v, want access-1/refresh-1", s)
	}

	// Reusing the rotated-out token is a terminal 4xx.
	_, err = c.RefreshSession(ctx, "refresh-0")
	apiErr, ok := supabase.AsAPIError(err)
	if !ok || apiErr.Status != 400 || apiErr.Code != "refresh_token_already_used" {
		t.Fatalf("reuse: err = %v, want 400 refresh_token_already_used", err)
	}
	if supabase.IsUnauthorized(err) {
		t.Error("a rejected refresh token must not be classified as an expired access token")
	}
}

func TestRefreshSession_RequiresToken(t *testing.T) {
	if _, err := supabase.New("http://unused", "anon", nil).RefreshSession(context.Background(), ""); err == nil {
		t.Fatal("expected an error for an empty refresh token")
	}
}

func TestInvokeFunction_Statuses(t *testing.T) {
	fake := supabasetest.New(t)
	fake.Handle("POST", "/functions/v1/agent-login",
		supabasetest.Response{Status: 429, Body: `{"error":"Too many failed attempts"}`},
		supabasetest.Response{Body: `{"access_token":"a","refresh_token":"r","expires_in":60}`},
	)
	c := fake.Client(nil)

	var out struct {
		AccessToken string `json:"access_token"`
	}
	err := c.InvokeFunction(context.Background(), "agent-login", map[string]string{"agent_id": "x"}, &out)
	if supabase.StatusCode(err) != 429 {
		t.Fatalf("first call: err = %v, want status 429", err)
	}
	if err := c.InvokeFunction(context.Background(), "agent-login", map[string]string{"agent_id": "x"}, &out); err != nil || out.AccessToken != "a" {
		t.Fatalf("second call: %v, token %q", err, out.AccessToken)
	}
}
