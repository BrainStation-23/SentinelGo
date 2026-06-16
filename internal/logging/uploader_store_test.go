package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/models"
	"sentinelgo/internal/store"
)

const poisonMarker = "POISON"

// newStoreUploader returns an uploader posting to srv plus a fresh audit-log store.
func newStoreUploader(t *testing.T, srv *httptest.Server) (*Uploader, *store.AuditLogStore) {
	t.Helper()
	cfg := &config.Config{
		SupabaseURL:    srv.URL,
		DeviceID:       "test-device",
		AccessToken:    "test-token",
		CurrentVersion: "test",
	}
	s, err := store.NewAuditLogStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewAuditLogStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return NewUploader(cfg, &statsCounter{}), s
}

func storeLog(eventType string, eventData string) models.AuditLog {
	return models.AuditLog{
		EventType:   eventType,
		Severity:    "low",
		LogCategory: models.LogCategorySystem,
		Source:      "test",
		DeviceID:    "test-device",
		OSType:      "linux",
		Timestamp:   "2024-01-01T00:00:0" + eventType[len(eventType)-1:] + "Z",
		EventData:   json.RawMessage(eventData),
	}
}

// TestUploadFromStore_IsolatesPoisonRow verifies that a single backend-rejected (4xx)
// row is dead-lettered while the rest of the batch uploads successfully.
func TestUploadFromStore_IsolatesPoisonRow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte(poisonMarker)) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u, s := newStoreUploader(t, srv)

	if err := s.Insert([]models.AuditLog{
		storeLog("evt1", `{"ok":1}`),
		storeLog("evt2", `{"marker":"POISON"}`),
		storeLog("evt3", `{"ok":3}`),
		storeLog("evt4", `{"ok":4}`),
	}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	uploaded, err := u.UploadFromStore(ctx, s)
	if err != nil {
		t.Fatalf("UploadFromStore: %v", err)
	}
	if uploaded != 3 {
		t.Errorf("uploaded = %d, want 3 (one poison row dead-lettered)", uploaded)
	}

	if n, _ := s.Count(); n != 0 {
		t.Errorf("pending queue = %d, want 0 (all rows resolved)", n)
	}
	if n, _ := s.DeadLetterCount(); n != 1 {
		t.Errorf("dead-letter count = %d, want 1", n)
	}
}

// TestUploadFromStore_TransientLeavesRows verifies that a persistent 5xx leaves rows in
// the queue (no data loss) and surfaces an error, rather than dead-lettering them.
func TestUploadFromStore_TransientLeavesRows(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	u, s := newStoreUploader(t, srv)
	if err := s.Insert([]models.AuditLog{
		storeLog("evt1", `{"ok":1}`),
		storeLog("evt2", `{"ok":2}`),
	}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	// 500 ms expires during the 1 s retry backoff, returning a transient error.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	uploaded, err := u.UploadFromStore(ctx, s)
	if err == nil {
		t.Fatal("expected a transient error on persistent 500, got nil")
	}
	if uploaded != 0 {
		t.Errorf("uploaded = %d, want 0", uploaded)
	}
	if n, _ := s.Count(); n != 2 {
		t.Errorf("pending queue = %d, want 2 (rows retried next cycle)", n)
	}
	if n, _ := s.DeadLetterCount(); n != 0 {
		t.Errorf("dead-letter count = %d, want 0 (transient is not poison)", n)
	}
}

// TestUploadFromStore_AllSucceed is the happy path: every row uploads and the queue drains.
func TestUploadFromStore_AllSucceed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u, s := newStoreUploader(t, srv)
	if err := s.Insert([]models.AuditLog{
		storeLog("evt1", `{"ok":1}`),
		storeLog("evt2", `{"ok":2}`),
		storeLog("evt3", `{"ok":3}`),
	}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	uploaded, err := u.UploadFromStore(context.Background(), s)
	if err != nil {
		t.Fatalf("UploadFromStore: %v", err)
	}
	if uploaded != 3 {
		t.Errorf("uploaded = %d, want 3", uploaded)
	}
	if n, _ := s.Count(); n != 0 {
		t.Errorf("pending queue = %d, want 0", n)
	}
}
