package updater

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"sentinelgo/internal/config"
	"sentinelgo/internal/supabase"
)

// fakeRetrier mimics auth.Service.DoWithAuthRetry: on a 401 it "recovers" by
// swapping in a fresh token and retries once.
type fakeRetrier struct {
	cfg        *config.Config
	recoveries int
}

func (f *fakeRetrier) DoWithAuthRetry(_ context.Context, _ *config.Config, fn func() error) error {
	err := fn()
	if !supabase.IsUnauthorized(err) {
		return err
	}
	f.recoveries++
	f.cfg.SetTokens("fresh-token", "fresh-refresh")
	return fn()
}

func setRetrier(t *testing.T, r AuthRetrier) {
	t.Helper()
	SetAuthRetrier(r)
	t.Cleanup(func() { SetAuthRetrier(nil) })
}

// expiringRPCServer rejects any bearer other than "fresh-token" the way
// PostgREST rejects an expired JWT.
func expiringRPCServer(t *testing.T, hits *int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(hits, 1)
		if r.URL.Path != rpcPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer fresh-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":"PGRST301","message":"JWT expired"}`))
			return
		}
		body, _ := json.Marshal([]LatestRelease{sampleRelease()})
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// postgrest-go never checked the status, so a 401 surfaced as "parse RPC
// response: json: cannot unmarshal object". It must be a typed 401 now.
func TestFetchLatestRelease_401IsTyped(t *testing.T) {
	var hits int64
	srv := expiringRPCServer(t, &hits)
	cfg := &config.Config{SupabaseURL: srv.URL, SupabaseKey: "anon", AccessToken: "expired-token"}

	_, err := fetchLatestRelease(t.Context(), cfg)
	if !supabase.IsUnauthorized(err) {
		t.Fatalf("err = %v, want a typed 401", err)
	}
	if strings.Contains(err.Error(), "parse") {
		t.Errorf("err = %v, should not be a parse error", err)
	}
}

// With an AuthRetrier wired in, an agent whose token expired can still find
// (and therefore apply) an update.
func TestFetchLatestRelease_RecoversExpiredToken(t *testing.T) {
	var hits int64
	srv := expiringRPCServer(t, &hits)
	cfg := &config.Config{SupabaseURL: srv.URL, SupabaseKey: "anon", AccessToken: "expired-token"}
	r := &fakeRetrier{cfg: cfg}
	setRetrier(t, r)

	got, err := fetchLatestRelease(t.Context(), cfg)
	if err != nil {
		t.Fatalf("fetchLatestRelease: %v", err)
	}
	if got == nil || got.Version != sampleRelease().Version {
		t.Fatalf("release = %+v", got)
	}
	if r.recoveries != 1 || atomic.LoadInt64(&hits) != 2 {
		t.Errorf("recoveries = %d, requests = %d; want 1 and 2", r.recoveries, atomic.LoadInt64(&hits))
	}
}

// The release RPC's wire shape must not change: same path, method, body keys
// and auth headers as the postgrest-go call it replaces.
func TestFetchLatestRelease_WireShape(t *testing.T) {
	var gotMethod, gotAuth, gotKey string
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != rpcPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gotMethod, gotAuth, gotKey = r.Method, r.Header.Get("Authorization"), r.Header.Get("apikey")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	cfg := &config.Config{SupabaseURL: srv.URL, SupabaseKey: "anon-key", AccessToken: "jwt"}
	if _, err := fetchLatestRelease(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotAuth != "Bearer jwt" || gotKey != "anon-key" {
		t.Errorf("method=%s Authorization=%q apikey=%q", gotMethod, gotAuth, gotKey)
	}
	if gotBody["p_platform"] == "" || gotBody["p_arch"] == "" || len(gotBody) != 2 {
		t.Errorf("body = %v, want exactly p_platform and p_arch", gotBody)
	}
}
