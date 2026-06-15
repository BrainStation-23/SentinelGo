package logging

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"sentinelgo/internal/config"
	"sentinelgo/internal/models"
)

// stubAuth is a test double for the uploader's authRetrier. When healthy is
// false the uploader must not touch the network.
type stubAuth struct {
	healthy   bool
	retryHits int64
}

func (s *stubAuth) DoWithAuthRetry(_ context.Context, _ *config.Config, fn func() error) error {
	atomic.AddInt64(&s.retryHits, 1)
	return fn()
}

func (s *stubAuth) Healthy() bool { return s.healthy }

// TestUpload_DegradedAuth_NoNetwork proves the "stop hammering" behaviour: when
// the session is unrecoverable the uploader defers (returns 0, nil) and makes no
// HTTP calls, leaving the logs to be retried once auth recovers.
func TestUpload_DegradedAuth_NoNetwork(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.Config{SupabaseURL: srv.URL, DeviceID: "test-device", AccessToken: "t", CurrentVersion: "test"}
	u := NewUploader(cfg, &statsCounter{})
	u.SetAuth(&stubAuth{healthy: false})

	logs := []models.AuditLog{makeTestLog(models.LogCategorySystem), makeTestLog(models.LogCategorySecurity)}

	n, err := u.Upload(context.Background(), logs)
	if err != nil {
		t.Fatalf("Upload() unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("Upload() uploaded %d logs while auth degraded, want 0", n)
	}
	if got := atomic.LoadInt64(&hits); got != 0 {
		t.Errorf("uploader made %d HTTP calls while auth degraded, want 0 (hammering not stopped)", got)
	}
}

// TestUpload_HealthyAuth_UsesRetryWrapper confirms that when auth is healthy the
// upload goes through the DoWithAuthRetry wrapper and reaches the network.
func TestUpload_HealthyAuth_UsesRetryWrapper(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.Config{SupabaseURL: srv.URL, DeviceID: "test-device", AccessToken: "t", CurrentVersion: "test"}
	u := NewUploader(cfg, &statsCounter{})
	auth := &stubAuth{healthy: true}
	u.SetAuth(auth)

	logs := []models.AuditLog{makeTestLog(models.LogCategorySystem)}
	if _, err := u.Upload(context.Background(), logs); err != nil {
		t.Fatalf("Upload() unexpected error: %v", err)
	}
	if atomic.LoadInt64(&auth.retryHits) == 0 {
		t.Error("expected upload to go through DoWithAuthRetry when auth is set")
	}
	if atomic.LoadInt64(&hits) == 0 {
		t.Error("expected at least one HTTP call when auth is healthy")
	}
}
