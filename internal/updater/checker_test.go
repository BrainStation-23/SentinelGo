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

// TestCheckAndApply_NoSHA256 covers the newer-version-found-but-no-checksum
// fail-closed branch. It temporarily overrides config.Version (normally "dev"
// in test binaries, which always fails isNewerVersion) so the comparison
// reaches the SHA256 check — safely, since this branch returns before any
// backup/download/replace/restart step runs.
func TestCheckAndApply_NoSHA256(t *testing.T) {
	prevVersion := config.Version
	config.Version = "v1.0.0"
	t.Cleanup(func() { config.Version = prevVersion })

	release := sampleRelease()
	release.SHA256 = ""
	srv := newRPCServer(t, []LatestRelease{release}, http.StatusOK)
	defer srv.Close()

	cfg := &config.Config{SupabaseURL: srv.URL, SupabaseKey: "test-key"}
	err := CheckAndApply(t.Context(), cfg)
	if err == nil {
		t.Fatal("expected an error when the release manifest has no SHA256")
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

// TestCheckInternetWithHTTP_Reachable and _Unreachable below don't need
// SENTINELGO_UPDATER_NETWORK_TESTS: unlike CheckInternetConnectivity (which
// hardcodes port 443 on real hosts), CheckInternetWithHTTP takes the full
// Supabase URL as a parameter, so an httptest.Server gives real, deterministic
// coverage without touching a live third-party host.
func TestCheckInternetWithHTTP_Reachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if !CheckInternetWithHTTP(srv.URL) {
		t.Error("CheckInternetWithHTTP() = false, want true for a reachable server")
	}
}

// TestCheckInternetWithHTTP_AnyStatusIsReachable confirms the "any HTTP
// response means the host is up" semantics documented on the function: even a
// 404 still means the network path is open.
func TestCheckInternetWithHTTP_AnyStatusIsReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	if !CheckInternetWithHTTP(srv.URL) {
		t.Error("CheckInternetWithHTTP() = false, want true even for a 404 response")
	}
}

func TestCheckInternetWithHTTP_Unreachable(t *testing.T) {
	if CheckInternetWithHTTP("http://127.0.0.1:1") {
		t.Error("CheckInternetWithHTTP() = true, want false for an unreachable host")
	}
}
