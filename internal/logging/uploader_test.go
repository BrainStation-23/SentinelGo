package logging

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/models"
)

// newTestUploader creates an Uploader whose AuditLogService posts to srv.
func newTestUploader(srv *httptest.Server) *Uploader {
	cfg := &config.Config{
		SupabaseURL:    srv.URL,
		DeviceID:       "test-device",
		AccessToken:    "test-token",
		CurrentVersion: "test",
	}
	return NewUploader(cfg, &statsCounter{})
}

func makeTestLog(category string) models.AuditLog {
	return models.AuditLog{
		EventType:   "test_event",
		Severity:    "LOW",
		LogCategory: category,
		Source:      "test",
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}
}

// TestUpload_Empty verifies that uploading zero logs is a no-op with no HTTP calls.
func TestUpload_Empty(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u := newTestUploader(srv)
	n, err := u.Upload(context.Background(), nil)
	if err != nil {
		t.Fatalf("Upload(nil) unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("Upload(nil) = %d, want 0", n)
	}
	if hits != 0 {
		t.Errorf("expected 0 HTTP calls for empty log slice, got %d", hits)
	}
}

// TestUpload_SingleBatch_Success verifies that a batch smaller than maxBatchSize
// is sent in one request and the uploaded count is returned.
func TestUpload_SingleBatch_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u := newTestUploader(srv)
	logs := []models.AuditLog{
		makeTestLog(models.LogCategorySystem),
		makeTestLog(models.LogCategorySecurity),
		makeTestLog(models.LogCategoryNetwork),
	}

	n, err := u.Upload(context.Background(), logs)
	if err != nil {
		t.Fatalf("Upload() unexpected error: %v", err)
	}
	if n != 3 {
		t.Errorf("Upload() = %d, want 3", n)
	}
	if got := u.stats.snapshot().LogsUploaded; got != 3 {
		t.Errorf("stats.uploaded = %d, want 3", got)
	}
}

// TestUpload_SingleBatch_ServerError verifies that a server error results in
// (0, err). A short context timeout cuts off the retry backoff so the test
// returns quickly instead of waiting for the full 1+2 s backoff.
func TestUpload_SingleBatch_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	u := newTestUploader(srv)
	logs := []models.AuditLog{makeTestLog(models.LogCategorySystem)}

	// 500 ms is long enough for the first HTTP round-trip to localhost, yet short
	// enough to expire during the 1-second retry backoff.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	n, err := u.Upload(ctx, logs)
	if n != 0 {
		t.Errorf("Upload() on server error = %d, want 0", n)
	}
	if err == nil {
		t.Error("expected error for server 500, got nil")
	}
	if got := u.stats.snapshot().UploadErrors; got == 0 {
		t.Error("expected non-zero UploadErrors in stats")
	}
}

// TestUpload_RetryOnTransientError verifies that a single transient server error
// is retried and the batch ultimately succeeds. The first request returns 500;
// subsequent requests return 200.
func TestUpload_RetryOnTransientError(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		if hits == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u := newTestUploader(srv)
	logs := []models.AuditLog{
		makeTestLog(models.LogCategorySystem),
		makeTestLog(models.LogCategorySecurity),
	}

	// Allow enough time for at least one retry (initial 1 s backoff).
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	n, err := u.Upload(ctx, logs)
	if err != nil {
		t.Fatalf("Upload() expected success after retry, got: %v", err)
	}
	if n != 2 {
		t.Errorf("Upload() = %d, want 2", n)
	}
	if hits < 2 {
		t.Errorf("expected at least 2 HTTP hits (1 error + 1 success), got %d", hits)
	}
	snap := u.stats.snapshot()
	// UploadErrors counts only batches that fail all retries; a batch that
	// eventually succeeds is not an error at the stats level.
	if snap.LogsUploaded != 2 {
		t.Errorf("stats.LogsUploaded = %d, want 2", snap.LogsUploaded)
	}
}

// TestUpload_TwoBatches_Success verifies that > maxBatchSize logs are split into
// two separate HTTP requests and all are counted as uploaded.
func TestUpload_TwoBatches_Success(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u := newTestUploader(srv)

	// 105 logs → two batches: one of maxBatchSize (100) and one of 5.
	logs := make([]models.AuditLog, 105)
	for i := range logs {
		logs[i] = makeTestLog(models.LogCategorySystem)
	}

	n, err := u.Upload(context.Background(), logs)
	if err != nil {
		t.Fatalf("Upload() unexpected error: %v", err)
	}
	if n != 105 {
		t.Errorf("Upload() = %d, want 105", n)
	}
	if hits != 2 {
		t.Errorf("expected 2 HTTP calls for 105 logs, got %d", hits)
	}
	if got := u.stats.snapshot().LogsUploaded; got != 105 {
		t.Errorf("stats.uploaded = %d, want 105", got)
	}
}
