package updater

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"
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
		fmt.Fprintf(w, "%s  %s\n", expectedChecksum, binaryName)
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
		fmt.Fprintf(w, "deadbeef1234  sentinelgo-linux-arm64\n")
		fmt.Fprintf(w, "%s  %s\n", expected, pattern)
		fmt.Fprintf(w, "cafebabe5678  sentinelgo-darwin-amd64\n")
	}))
	defer srv.Close()

	got := downloadAndParseChecksumFile(srv.URL)
	if got != expected {
		t.Errorf("got %q, want %q", got, expected)
	}
}

func TestDownloadAndParseChecksumFile_NoMatchingEntry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "abcdef  sentinelgo-plan9-amd64")
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
		fmt.Fprintln(w, "")                               // blank line
		fmt.Fprintln(w, "notahashline")                   // no spaces
		fmt.Fprintln(w, "  ")                             // only whitespace
		fmt.Fprintf(w, "%s  %s\n", expected, binaryName) // valid matching entry
		fmt.Fprintln(w, "justonefield")                   // no separator
	}))
	defer srv.Close()

	got := downloadAndParseChecksumFile(srv.URL)
	if got != expected {
		t.Errorf("got %q, want %q", got, expected)
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
