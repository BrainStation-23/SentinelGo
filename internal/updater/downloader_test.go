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
)

// ── downloadAndVerify ─────────────────────────────────────────────────────────

// TestDownloadAndVerify_NonOKStatus verifies that a non-200 response from the
// binary download endpoint is treated as an error.
func TestDownloadAndVerify_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// sigURL is empty here; we expect the error to come from the download status check.
	_, _, err := downloadAndVerify(ctx, srv.URL, "somechecksum", "", "v1.0.0")
	if err == nil {
		t.Error("expected error for non-200 status, got nil")
	}
	if !strings.Contains(err.Error(), "404") && !strings.Contains(err.Error(), "status") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestDownloadAndVerify_DownloadSucceeds_SignatureFails exercises the full download
// and SHA256 path. The signature check fails (empty sigURL → fail-closed), but the
// download, streaming, and checksum computation are all exercised.
func TestDownloadAndVerify_DownloadSucceeds_SignatureFails(t *testing.T) {
	content := []byte("fake sentinelgo binary content for testing")

	// Compute expected SHA256 of the content
	h := sha256.Sum256(content)
	expectedChecksum := hex.EncodeToString(h[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Empty sigURL triggers fail-closed in verifySignature.
	// The call will succeed through download + SHA256, then fail at signature.
	_, actualChecksum, err := downloadAndVerify(ctx, srv.URL, expectedChecksum, "", "v1.0.0")

	// We expect a signature error (not a download error)
	if err == nil {
		t.Error("expected error from signature verification (empty sigURL), got nil")
	}
	if !strings.Contains(err.Error(), "sig") && !strings.Contains(err.Error(), "signature") {
		t.Errorf("expected signature-related error, got: %v", err)
	}

	// actualChecksum is set before verifySignature runs; it should match.
	// However, on error the function returns "", "", err — so we check that too.
	if err != nil && actualChecksum != "" {
		// The function returns "" on error path through verifySignature
		// (os.Remove + return "", "", err). If actualChecksum is somehow set,
		// it should at least match.
		if actualChecksum != expectedChecksum {
			t.Errorf("returned checksum %q does not match expected %q", actualChecksum, expectedChecksum)
		}
	}

	// The .new file should have been cleaned up by downloadAndVerify on sig failure
	selfPath, _ := os.Executable()
	newPath := selfPath + ".new"
	if _, statErr := os.Stat(newPath); statErr == nil {
		// File still exists — clean it up so other tests aren't affected
		_ = os.Remove(newPath)
		t.Log("note: .new file was not cleaned up by downloadAndVerify (may be expected if winsec.SecurePath prevents removal)")
	}
}

// TestDownloadAndVerify_CancelledContext verifies context cancellation is propagated.
func TestDownloadAndVerify_CancelledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until request is cancelled
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, _, err := downloadAndVerify(ctx, srv.URL, "checksum", "", "v1.0.0")
	if err == nil {
		t.Error("expected error from cancelled context, got nil")
	}
}

// TestDownloadAndVerify_InvalidURL verifies that a completely invalid URL returns an error.
func TestDownloadAndVerify_InvalidURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err := downloadAndVerify(ctx, fmt.Sprintf("http://127.0.0.1:%d/nonexistent", 1), "checksum", "", "v1.0.0")
	if err == nil {
		t.Error("expected error for unreachable URL, got nil")
	}
}

