package updater

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/config"
)

// ── selectAssetWithChecksum ────────────────────────────────────────────────────

func makeRelease(assets []Asset) *GitHubRelease {
	return &GitHubRelease{TagName: "v1.2.3", Assets: assets}
}

func TestSelectAssetWithChecksum_LinuxAMD64(t *testing.T) {
	rel := makeRelease([]Asset{
		{Name: "sentinelgo-linux-amd64", URL: "https://github.com/o/r/releases/download/v1.2.3/sentinelgo-linux-amd64"},
		{Name: "sentinelgo-linux-amd64.sig", URL: "https://github.com/o/r/releases/download/v1.2.3/sentinelgo-linux-amd64.sig"},
	})

	assetURL, checksum, sigURL, err := selectAssetWithChecksum(rel, "linux", "amd64")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if assetURL == "" {
		t.Error("expected non-empty assetURL")
	}
	if sigURL == "" {
		t.Error("expected non-empty sigURL")
	}
	// No SHA256SUMS in the release → checksum should be empty string
	if checksum != "" {
		t.Errorf("expected empty checksum (no SHA256SUMS asset), got %q", checksum)
	}
}

func TestSelectAssetWithChecksum_WindowsAMD64(t *testing.T) {
	rel := makeRelease([]Asset{
		{Name: "sentinelgo-windows-amd64.exe", URL: "https://github.com/o/r/releases/download/v1.2.3/sentinelgo-windows-amd64.exe"},
		{Name: "sentinelgo-windows-amd64.exe.sig", URL: "https://github.com/o/r/releases/download/v1.2.3/sentinelgo-windows-amd64.exe.sig"},
	})

	assetURL, _, sigURL, err := selectAssetWithChecksum(rel, "windows", "amd64")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if assetURL == "" {
		t.Error("expected non-empty assetURL")
	}
	if sigURL == "" {
		t.Error("expected non-empty sigURL")
	}
}

func TestSelectAssetWithChecksum_DarwinARM64(t *testing.T) {
	rel := makeRelease([]Asset{
		{Name: "sentinelgo-darwin-arm64", URL: "https://github.com/o/r/releases/download/v1.2.3/sentinelgo-darwin-arm64"},
	})

	assetURL, _, _, err := selectAssetWithChecksum(rel, "darwin", "arm64")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if assetURL == "" {
		t.Error("expected non-empty assetURL")
	}
}

func TestSelectAssetWithChecksum_NoMatchingAsset(t *testing.T) {
	rel := makeRelease([]Asset{
		{Name: "sentinelgo-linux-amd64", URL: "https://github.com/o/r/x"},
	})

	_, _, _, err := selectAssetWithChecksum(rel, "darwin", "arm64")
	if err == nil {
		t.Error("expected error when no matching asset found")
	}
}

func TestSelectAssetWithChecksum_UnsupportedOS(t *testing.T) {
	rel := makeRelease([]Asset{})

	_, _, _, err := selectAssetWithChecksum(rel, "plan9", "amd64")
	if err == nil {
		t.Error("expected error for unsupported OS")
	}
}

func TestSelectAssetWithChecksum_WithChecksumFile(t *testing.T) {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	var suffix string
	if goos == "windows" {
		suffix = ".exe"
	}
	binaryName := fmt.Sprintf("sentinelgo-%s-%s%s", goos, goarch, suffix)
	sigName := binaryName + ".sig"

	// Serve a fake SHA256SUMS file
	expectedChecksum := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "%s  %s\n", expectedChecksum, binaryName)
	}))
	defer srv.Close()

	rel := makeRelease([]Asset{
		{Name: binaryName, URL: "https://github.com/o/r/releases/download/v1.2.3/" + binaryName},
		{Name: sigName, URL: "https://github.com/o/r/releases/download/v1.2.3/" + sigName},
		{Name: "SHA256SUMS", URL: srv.URL + "/SHA256SUMS"},
	})

	assetURL, checksum, sigURL, err := selectAssetWithChecksum(rel, goos, goarch)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if assetURL == "" {
		t.Error("expected non-empty assetURL")
	}
	if sigURL == "" {
		t.Error("expected non-empty sigURL")
	}
	if checksum != expectedChecksum {
		t.Errorf("checksum = %q, want %q", checksum, expectedChecksum)
	}
}

// ── downloadAndParseChecksumFile ──────────────────────────────────────────────

func TestDownloadAndParseChecksumFile_ValidEntry(t *testing.T) {
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	pattern := fmt.Sprintf("sentinelgo-%s-%s", goos, goarch)

	expected := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Lines with other platforms + the matching line
		_, _ = fmt.Fprintf(w, "deadbeef1234  sentinelgo-linux-arm64\n")
		_, _ = fmt.Fprintf(w, "%s  %s\n", expected, pattern)
		_, _ = fmt.Fprintf(w, "cafebabe5678  sentinelgo-darwin-amd64\n")
	}))
	defer srv.Close()

	got := downloadAndParseChecksumFile(srv.URL)
	if got != expected {
		t.Errorf("got %q, want %q", got, expected)
	}
}

func TestDownloadAndParseChecksumFile_NoMatchingEntry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "abcdef  sentinelgo-plan9-amd64")
	}))
	defer srv.Close()

	got := downloadAndParseChecksumFile(srv.URL)
	if got != "" {
		t.Errorf("expected empty string for no match, got %q", got)
	}
}

func TestDownloadAndParseChecksumFile_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	got := downloadAndParseChecksumFile(srv.URL)
	if got != "" {
		t.Errorf("expected empty string on server error, got %q", got)
	}
}

func TestDownloadAndParseChecksumFile_InvalidURL(t *testing.T) {
	got := downloadAndParseChecksumFile("not-a-valid-url-%%%")
	if got != "" {
		t.Errorf("expected empty string for invalid URL, got %q", got)
	}
}

// ── CheckInternetConnectivity / CheckInternetWithHTTP (network-gated) ─────────

// requireNetworkInternal gates tests that require a live internet connection.
// Mirrors the requireNetwork helper in the external test package.
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

	result := CheckInternetConnectivity()
	t.Logf("CheckInternetConnectivity() = %v", result)
}

func TestCheckInternetWithHTTP(t *testing.T) {
	requireNetworkInternal(t)

	result := CheckInternetWithHTTP()
	t.Logf("CheckInternetWithHTTP() = %v", result)
}

// ── additional downloadAndParseChecksumFile edge cases ────────────────────────

// TestDownloadAndParseChecksumFile_EmptyFile verifies that an empty SHA256SUMS
// body is handled gracefully and returns an empty string.
func TestDownloadAndParseChecksumFile_EmptyFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		// empty body
	}))
	defer srv.Close()

	got := downloadAndParseChecksumFile(srv.URL)
	if got != "" {
		t.Errorf("expected empty string for empty SHA256SUMS, got %q", got)
	}
}

// TestDownloadAndParseChecksumFile_MalformedLines verifies that lines without
// the expected "hash  filename" format are skipped without panicking and the
// function still finds the matching entry among valid lines.
func TestDownloadAndParseChecksumFile_MalformedLines(t *testing.T) {
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	var suffix string
	if goos == "windows" {
		suffix = ".exe"
	}
	binaryName := fmt.Sprintf("sentinelgo-%s-%s%s", goos, goarch, suffix)
	expected := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// mix of garbage lines and one valid matching entry
		_, _ = fmt.Fprintln(w, "")                              // blank line
		_, _ = fmt.Fprintln(w, "notahashline")                  // no spaces
		_, _ = fmt.Fprintln(w, "  ")                            // only whitespace
		_, _ = fmt.Fprintf(w, "%s  %s\n", expected, binaryName) // valid matching entry
		_, _ = fmt.Fprintln(w, "justonefield")                  // no separator
	}))
	defer srv.Close()

	got := downloadAndParseChecksumFile(srv.URL)
	if got != expected {
		t.Errorf("got %q, want %q", got, expected)
	}
}

// ── fetchLatestRelease (apiClient injection) ──────────────────────────────────

// roundTripFunc is a one-shot http.RoundTripper backed by a function.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFetchLatestRelease_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v9.9.9","assets":[]}`))
	}))
	defer srv.Close()

	orig := apiClient
	apiClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			// Forward to local server
			newReq, _ := http.NewRequest(r.Method, srv.URL+r.URL.Path, r.Body)
			newReq = newReq.WithContext(r.Context())
			return http.DefaultTransport.RoundTrip(newReq)
		}),
	}
	defer func() { apiClient = orig }()

	cfg := &config.Config{GitHubOwner: "test-owner", GitHubRepo: "test-repo"}
	rel, err := fetchLatestRelease(t.Context(), cfg, "")
	if err != nil {
		t.Fatalf("fetchLatestRelease failed: %v", err)
	}
	if rel.TagName != "v9.9.9" {
		t.Errorf("TagName = %q, want v9.9.9", rel.TagName)
	}
}

func TestFetchLatestRelease_NotFound(t *testing.T) {
	orig := apiClient
	apiClient = &http.Client{
		Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       http.NoBody,
				Header:     make(http.Header),
			}, nil
		}),
	}
	defer func() { apiClient = orig }()

	cfg := &config.Config{GitHubOwner: "test-owner", GitHubRepo: "test-repo"}
	_, err := fetchLatestRelease(t.Context(), cfg, "")
	if err == nil {
		t.Fatal("expected error for 404 response, got nil")
	}
}

func TestFetchLatestRelease_InvalidJSON(t *testing.T) {
	orig := apiClient
	apiClient = &http.Client{
		Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{invalid-json`)),
				Header:     make(http.Header),
			}, nil
		}),
	}
	defer func() { apiClient = orig }()

	cfg := &config.Config{GitHubOwner: "test-owner", GitHubRepo: "test-repo"}
	_, err := fetchLatestRelease(t.Context(), cfg, "")
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestFetchLatestRelease_WithToken(t *testing.T) {
	var receivedAuth string
	orig := apiClient
	apiClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			receivedAuth = r.Header.Get("Authorization")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"tag_name":"v1.0.0","assets":[]}`)),
				Header:     make(http.Header),
			}, nil
		}),
	}
	defer func() { apiClient = orig }()

	cfg := &config.Config{GitHubOwner: "o", GitHubRepo: "r"}
	_, err := fetchLatestRelease(t.Context(), cfg, "my-token")
	if err != nil {
		t.Fatalf("fetchLatestRelease: %v", err)
	}
	if receivedAuth != "Bearer my-token" {
		t.Errorf("Authorization = %q, want Bearer my-token", receivedAuth)
	}
}

// ── AutoUpdateChecker (cancelled context) ─────────────────────────────────────

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

// ── CheckAndApply ─────────────────────────────────────────────────────────────

// TestCheckAndApply_DevBuild covers the "cannot compare versions" early-exit
// path. In test binaries config.Version == "dev", so isNewerVersion("v99.9.9",
// "dev") returns a parse error and CheckAndApply skips the update (returns nil).
func TestCheckAndApply_DevBuild(t *testing.T) {
	orig := apiClient
	apiClient = &http.Client{
		Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"tag_name":"v99.9.9","assets":[]}`)),
				Header:     make(http.Header),
			}, nil
		}),
	}
	defer func() { apiClient = orig }()

	cfg := &config.Config{GitHubOwner: "o", GitHubRepo: "r"}
	err := CheckAndApply(t.Context(), cfg, "")
	if err != nil {
		t.Errorf("CheckAndApply on dev build: got error %v, want nil", err)
	}
}

// TestCheckAndApply_FetchError verifies that a GitHub API failure is returned as
// an error.
func TestCheckAndApply_FetchError(t *testing.T) {
	orig := apiClient
	apiClient = &http.Client{
		Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       http.NoBody,
				Header:     make(http.Header),
			}, nil
		}),
	}
	defer func() { apiClient = orig }()

	cfg := &config.Config{GitHubOwner: "o", GitHubRepo: "r"}
	if err := CheckAndApply(t.Context(), cfg, ""); err == nil {
		t.Error("expected error for 500 fetch response, got nil")
	}
}

// ── CheckAndApplyWithRetry ────────────────────────────────────────────────────

// TestCheckAndApplyWithRetry_DevBuild verifies the retry wrapper returns nil
// when the underlying update is a no-op (dev build).
func TestCheckAndApplyWithRetry_DevBuild(t *testing.T) {
	orig := apiClient
	apiClient = &http.Client{
		Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"tag_name":"v99.9.9","assets":[]}`)),
				Header:     make(http.Header),
			}, nil
		}),
	}
	defer func() { apiClient = orig }()

	cfg := &config.Config{GitHubOwner: "o", GitHubRepo: "r"}
	if err := CheckAndApplyWithRetry(t.Context(), cfg, ""); err != nil {
		t.Errorf("CheckAndApplyWithRetry on dev build: got error %v, want nil", err)
	}
}

// TestCheckAndApplyWithRetry_ContextCancelledDuringBackoff verifies that a
// pre-cancelled context causes the retry loop to exit after the first attempt
// rather than sleeping through the backoff.
func TestCheckAndApplyWithRetry_ContextCancelledDuringBackoff(t *testing.T) {
	callCount := 0
	orig := apiClient
	apiClient = &http.Client{
		Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			callCount++
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       http.NoBody,
				Header:     make(http.Header),
			}, nil
		}),
	}
	defer func() { apiClient = orig }()

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // already cancelled — backoff select fires ctx.Done() immediately

	cfg := &config.Config{GitHubOwner: "o", GitHubRepo: "r"}
	_ = CheckAndApplyWithRetry(ctx, cfg, "")
	// With a pre-cancelled context the loop exits after attempt 1 (the ctx.Done
	// select in the backoff fires before a second attempt begins).
	if callCount > 1 {
		t.Errorf("expected at most 1 HTTP call with pre-cancelled context, got %d", callCount)
	}
}

// ── additional selectAssetWithChecksum cases ──────────────────────────────────

// TestSelectAssetWithChecksum_LinuxARM64 verifies that an arm64 Linux binary is
// selected when GOOS=linux and GOARCH=arm64.
func TestSelectAssetWithChecksum_LinuxARM64(t *testing.T) {
	rel := makeRelease([]Asset{
		{Name: "sentinelgo-linux-arm64", URL: "https://github.com/o/r/releases/download/v1.2.3/sentinelgo-linux-arm64"},
		{Name: "sentinelgo-linux-arm64.sig", URL: "https://github.com/o/r/releases/download/v1.2.3/sentinelgo-linux-arm64.sig"},
	})

	assetURL, _, sigURL, err := selectAssetWithChecksum(rel, "linux", "arm64")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if assetURL == "" {
		t.Error("expected non-empty assetURL for linux/arm64")
	}
	if sigURL == "" {
		t.Error("expected non-empty sigURL for linux/arm64")
	}
}
