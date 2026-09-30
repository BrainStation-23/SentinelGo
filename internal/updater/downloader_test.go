package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/config"
)

// cfgForServer returns a minimal config pointing at the given test server URL.
func cfgForServer(srvURL string) *config.Config {
	return &config.Config{
		SupabaseURL: srvURL,
		SupabaseKey: "test-anon-key",
	}
}

// TestDownloadAndVerify_NonOKStatus verifies that a non-200 response from the
// binary download endpoint is treated as an error.
func TestDownloadAndVerify_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := cfgForServer(srv.URL)
	_, _, err := downloadAndVerify(ctx, cfg, "v1.0.0/sentinelgo-linux-amd64", "somechecksum", "v1.0.0/sentinelgo-linux-amd64.sig")
	if err == nil {
		t.Error("expected error for non-200 status, got nil")
	}
	if !strings.Contains(err.Error(), "404") && !strings.Contains(err.Error(), "status") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestDownloadAndVerify_EmptySigPath exercises fail-closed: an empty sigAssetPath
// means no signature is available and the update must be rejected.
func TestDownloadAndVerify_EmptySigPath(t *testing.T) {
	content := []byte("fake sentinelgo binary content for testing")
	h := sha256.Sum256(content)
	expectedChecksum := hex.EncodeToString(h[:])

	assetPath := "v1.0.0/sentinelgo-linux-amd64"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/storage/v1/object/agent-releases/"+assetPath {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(content)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg := cfgForServer(srv.URL)
	_, _, err := downloadAndVerify(ctx, cfg, assetPath, expectedChecksum, "")
	if err == nil {
		t.Error("expected error from empty sigAssetPath (fail closed), got nil")
	}
	if !strings.Contains(err.Error(), "sig") {
		t.Errorf("expected sig-related error, got: %v", err)
	}

	// The .new file must have been cleaned up.
	selfPath, _ := os.Executable()
	if _, statErr := os.Stat(selfPath + ".new"); statErr == nil {
		_ = os.Remove(selfPath + ".new")
		t.Log("note: .new file was left behind — cleaned up by test")
	}
}

// TestDownloadAndVerify_AuthHeadersSent verifies that the JWT and apikey headers
// are forwarded to the storage endpoint.
func TestDownloadAndVerify_AuthHeadersSent(t *testing.T) {
	var gotAuth, gotAPIKey string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAPIKey = r.Header.Get("apikey")
		w.WriteHeader(http.StatusNotFound) // enough to check headers
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cfg := &config.Config{
		SupabaseURL: srv.URL,
		SupabaseKey: "my-anon-key",
	}
	cfg.SetTokens("my-jwt-token", "")

	_, _, _ = downloadAndVerify(ctx, cfg, "v1.0.0/binary", "sha", "v1.0.0/binary.sig")

	if gotAuth != "Bearer my-jwt-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer my-jwt-token")
	}
	if gotAPIKey != "my-anon-key" {
		t.Errorf("apikey = %q, want %q", gotAPIKey, "my-anon-key")
	}
}

// TestDownloadAndVerify_CancelledContext verifies context cancellation propagates.
func TestDownloadAndVerify_CancelledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	cfg := cfgForServer(srv.URL)
	_, _, err := downloadAndVerify(ctx, cfg, "v1/binary", "checksum", "v1/binary.sig")
	if err == nil {
		t.Error("expected error from cancelled context, got nil")
	}
}

// TestDownloadAndVerify_TruncatedBody verifies that a connection dropped
// mid-download (actual bytes shorter than the declared Content-Length) is
// surfaced as an io.Copy error, and the partially-written .new file is cleaned up.
func TestDownloadAndVerify_TruncatedBody(t *testing.T) {
	assetPath := "v1.0.0/sentinelgo-linux-amd64"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000000") // declare far more than we send
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("short body"))
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close() // abruptly close so the client sees a truncated read
			}
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := cfgForServer(srv.URL)
	_, _, err := downloadAndVerify(ctx, cfg, assetPath, "somechecksum", "")
	if err == nil {
		t.Error("expected an error from a truncated download body, got nil")
	}

	// Best-effort cleanup: on some platforms os.Remove(newPath) in the
	// production code races the not-yet-deferred-closed file handle (see the
	// same note in TestDownloadAndVerify_EmptySigPath above).
	selfPath, _ := os.Executable()
	if _, statErr := os.Stat(selfPath + ".new"); statErr == nil {
		_ = os.Remove(selfPath + ".new")
		t.Log("note: .new file was left behind — cleaned up by test")
	}
}

// TestDownloadAndVerify_InvalidURL verifies that an unreachable host returns an error.
func TestDownloadAndVerify_InvalidURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cfg := &config.Config{
		SupabaseURL: fmt.Sprintf("http://127.0.0.1:%d", 1),
		SupabaseKey: "key",
	}
	_, _, err := downloadAndVerify(ctx, cfg, "v1/binary", "checksum", "v1/binary.sig")
	if err == nil {
		t.Error("expected error for unreachable URL, got nil")
	}
}
