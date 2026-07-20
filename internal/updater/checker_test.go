package updater

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"sentinelgo/internal/config"
)

// rpcPath is the PostgREST endpoint the updater calls.
const rpcPath = "/rest/v1/rpc/get_latest_agent_release"

// newRPCServer returns an httptest.Server that serves the Supabase RPC
// endpoint. rows is the JSON array returned in the body (pass nil for empty).
func newRPCServer(t *testing.T, rows []LatestRelease, statusCode int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != rpcPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if statusCode == http.StatusOK {
			body, _ := json.Marshal(rows)
			_, _ = w.Write(body)
		}
	}))
}

// sampleRelease returns a LatestRelease with plausible test values.
func sampleRelease() LatestRelease {
	return LatestRelease{
		Version:     "v99.9.9",
		AssetName:   "sentinelgo-linux-amd64",
		AssetPath:   "v99.9.9/sentinelgo-linux-amd64",
		SHA256:      "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		Size:        1024,
		ContentType: "application/octet-stream",
	}
}

// ── fetchLatestRelease ────────────────────────────────────────────────────────

func TestFetchLatestRelease_Happy(t *testing.T) {
	want := sampleRelease()
	srv := newRPCServer(t, []LatestRelease{want}, http.StatusOK)
	defer srv.Close()

	cfg := &config.Config{SupabaseURL: srv.URL, SupabaseKey: "test-key"}
	got, err := fetchLatestRelease(t.Context(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil release, got nil")
		return // Early return to satisfy staticcheck
	}
	if got.Version != want.Version {
		t.Errorf("Version = %q, want %q", got.Version, want.Version)
	}
	if got.AssetPath != want.AssetPath {
		t.Errorf("AssetPath = %q, want %q", got.AssetPath, want.AssetPath)
	}
	if got.SHA256 != want.SHA256 {
		t.Errorf("SHA256 = %q, want %q", got.SHA256, want.SHA256)
	}
}

func TestFetchLatestRelease_Empty(t *testing.T) {
	srv := newRPCServer(t, nil, http.StatusOK)
	defer srv.Close()

	cfg := &config.Config{SupabaseURL: srv.URL, SupabaseKey: "test-key"}
	got, err := fetchLatestRelease(t.Context(), cfg)
	if err != nil {
		t.Fatalf("unexpected error on empty result: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for empty result, got %+v", got)
	}
}

func TestFetchLatestRelease_RPCError(t *testing.T) {
	srv := newRPCServer(t, nil, http.StatusInternalServerError)
	defer srv.Close()

	cfg := &config.Config{SupabaseURL: srv.URL, SupabaseKey: "test-key"}
	_, err := fetchLatestRelease(t.Context(), cfg)
	if err == nil {
		t.Error("expected error for 500 RPC response, got nil")
	}
}

// ── CheckAndApply ─────────────────────────────────────────────────────────────

// TestCheckAndApply_DevBuild covers the "cannot compare versions" early-exit
// path. config.Version is "dev" in test binaries, so isNewerVersion returns a
// parse error and CheckAndApply skips the update (returns nil).
func TestCheckAndApply_DevBuild(t *testing.T) {
	srv := newRPCServer(t, []LatestRelease{sampleRelease()}, http.StatusOK)
	defer srv.Close()

	cfg := &config.Config{SupabaseURL: srv.URL, SupabaseKey: "test-key"}
	if err := CheckAndApply(t.Context(), cfg); err != nil {
		t.Errorf("CheckAndApply on dev build: got error %v, want nil", err)
	}
}

// TestCheckAndApply_NoRelease verifies that an empty RPC response (no release
// configured yet) is treated as a no-op and returns nil.
func TestCheckAndApply_NoRelease(t *testing.T) {
	srv := newRPCServer(t, nil, http.StatusOK)
	defer srv.Close()

	cfg := &config.Config{SupabaseURL: srv.URL, SupabaseKey: "test-key"}
	if err := CheckAndApply(t.Context(), cfg); err != nil {
		t.Errorf("CheckAndApply with no release: got error %v, want nil", err)
	}
}

// TestCheckAndApply_FetchError verifies that an RPC failure is returned as an error.
func TestCheckAndApply_FetchError(t *testing.T) {
	srv := newRPCServer(t, nil, http.StatusInternalServerError)
	defer srv.Close()

	cfg := &config.Config{SupabaseURL: srv.URL, SupabaseKey: "test-key"}
	if err := CheckAndApply(t.Context(), cfg); err == nil {
		t.Error("expected error for 500 RPC response, got nil")
	}
}

// ── CheckAndApplyWithRetry ────────────────────────────────────────────────────

func TestCheckAndApplyWithRetry_DevBuild(t *testing.T) {
	srv := newRPCServer(t, []LatestRelease{sampleRelease()}, http.StatusOK)
	defer srv.Close()

	cfg := &config.Config{SupabaseURL: srv.URL, SupabaseKey: "test-key"}
	if err := CheckAndApplyWithRetry(t.Context(), cfg); err != nil {
		t.Errorf("CheckAndApplyWithRetry on dev build: got error %v, want nil", err)
	}
}

// TestCheckAndApplyWithRetry_ContextCancelledDuringBackoff verifies that a
// pre-cancelled context exits after the first attempt rather than sleeping
// through the full backoff.
func TestCheckAndApplyWithRetry_ContextCancelledDuringBackoff(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == rpcPath {
			callCount++
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // already cancelled — backoff select fires ctx.Done() immediately

	cfg := &config.Config{SupabaseURL: srv.URL, SupabaseKey: "test-key"}
	_ = CheckAndApplyWithRetry(ctx, cfg)

	if callCount > 1 {
		t.Errorf("expected at most 1 RPC call with pre-cancelled context, got %d", callCount)
	}
}

// ── backoffDuration ───────────────────────────────────────────────────────────

func TestBackoffDuration_Caps(t *testing.T) {
	cases := []struct {
		n    int
		want time.Duration
	}{
		{0, 5 * time.Second},
		{1, 10 * time.Second},
		{2, 20 * time.Second},
		{3, 40 * time.Second},
		{4, 80 * time.Second},
		{10, 5 * time.Minute}, // capped
		{20, 5 * time.Minute}, // capped
	}
	for _, tc := range cases {
		got := backoffDuration(tc.n)
		if got != tc.want {
			t.Errorf("backoffDuration(%d) = %v, want %v", tc.n, got, tc.want)
		}
	}
}

// ── AutoUpdateChecker ─────────────────────────────────────────────────────────

func TestAutoUpdateChecker_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // already cancelled

	done := make(chan struct{})
	go func() {
		defer close(done)
		AutoUpdateChecker(ctx, &config.Config{})
	}()

	select {
	case <-done:
		// OK — returned promptly
	case <-time.After(5 * time.Second):
		t.Error("AutoUpdateChecker with cancelled context did not return within 5s")
	}
}

// ── CheckInternetConnectivity / CheckInternetWithHTTP (network-gated) ─────────

func requireNetworkInternal(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping network-dependent test in short mode")
	}
	if os.Getenv("SENTINELGO_UPDATER_NETWORK_TESTS") != "1" {
		t.Skip("skipping network-dependent test; set SENTINELGO_UPDATER_NETWORK_TESTS=1 to run")
	}
}

func TestCheckInternetConnectivity(t *testing.T) {
	requireNetworkInternal(t)
	result := CheckInternetConnectivity("https://supabase.co")
	t.Logf("CheckInternetConnectivity() = %v", result)
}

func TestCheckInternetWithHTTP(t *testing.T) {
	requireNetworkInternal(t)
	result := CheckInternetWithHTTP("https://supabase.co")
	t.Logf("CheckInternetWithHTTP() = %v", result)
}
