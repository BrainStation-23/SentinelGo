package native

// White-box tests for the sync-software handler.
// Using package native (not native_test) to access the test seams.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	swsvc "sentinelgo/internal/service/software"

	"sentinelgo/internal/config"
	"sentinelgo/internal/store"
	"sentinelgo/internal/taskstore"
)

func testSwCfg(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{
		Path:        dir + "/config.json",
		SupabaseURL: "https://test.supabase.co",
		DeviceID:    "test-device",
		AccessToken: "test-token",
	}
}

// stubSoftware swaps the handler's collect/sync seams for the duration of a test.
func stubSoftware(t *testing.T, list []swsvc.SoftwareInfo, complete bool, sync func(context.Context, *swsvc.SoftwareService, *config.Config, []swsvc.SoftwareInfo, bool) (bool, error)) {
	t.Helper()
	origList := getSoftwareListFn
	origSync := syncSoftwareFn
	t.Cleanup(func() {
		getSoftwareListFn = origList
		syncSoftwareFn = origSync
	})
	getSoftwareListFn = func(_ *swsvc.SoftwareService) ([]swsvc.SoftwareInfo, bool) { return list, complete }
	syncSoftwareFn = sync
}

func TestSyncSoftwareHandler_Slugs(t *testing.T) {
	h := &syncSoftwareHandler{}
	found := false
	for _, s := range h.Slugs() {
		if s == "sync-software" {
			found = true
		}
	}
	if !found {
		t.Errorf("Slugs() does not contain 'sync-software': %v", h.Slugs())
	}
}

func TestSyncSoftwareHandler_EmptyCatalog_ReturnsSuccess(t *testing.T) {
	stubSoftware(t, nil, true, func(_ context.Context, _ *swsvc.SoftwareService, _ *config.Config, _ []swsvc.SoftwareInfo, _ bool) (bool, error) {
		return false, errors.New("sync must not be called for empty list")
	})

	h := &syncSoftwareHandler{}
	note, err := h.Run(context.Background(), testSwCfg(t), taskstore.Task{})
	if err != nil {
		t.Fatalf("expected no error for empty list, got: %v", err)
	}
	if note == "" {
		t.Error("expected non-empty note for empty list")
	}
}

func TestSyncSoftwareHandler_SendFails_ReturnsError(t *testing.T) {
	sendErr := errors.New("RPC unavailable")
	stubSoftware(t,
		[]swsvc.SoftwareInfo{{Name: "fake-pkg", Source: "programs", InstalledVersion: "1.0"}},
		true,
		func(_ context.Context, _ *swsvc.SoftwareService, _ *config.Config, _ []swsvc.SoftwareInfo, _ bool) (bool, error) {
			return false, sendErr
		})

	h := &syncSoftwareHandler{}
	_, err := h.Run(context.Background(), testSwCfg(t), taskstore.Task{})
	if err == nil {
		t.Fatal("expected error when send fails")
	}
	if !errors.Is(err, sendErr) {
		t.Errorf("expected wrapped sendErr, got: %v", err)
	}
}

func TestSyncSoftwareHandler_Sent_ReportsCount(t *testing.T) {
	stubSoftware(t,
		[]swsvc.SoftwareInfo{{Name: "a"}, {Name: "b"}, {Name: "c"}},
		true,
		func(_ context.Context, _ *swsvc.SoftwareService, _ *config.Config, _ []swsvc.SoftwareInfo, _ bool) (bool, error) {
			return false, nil // sent (not skipped)
		})

	h := &syncSoftwareHandler{}
	note, err := h.Run(context.Background(), testSwCfg(t), taskstore.Task{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(note, "synced successfully") || !strings.Contains(note, "3 items") {
		t.Errorf("note = %q, want 'synced successfully: 3 items'", note)
	}
}

func TestSyncSoftwareHandler_Skipped_ReportsUnchanged(t *testing.T) {
	stubSoftware(t,
		[]swsvc.SoftwareInfo{{Name: "a"}, {Name: "b"}},
		true,
		func(_ context.Context, _ *swsvc.SoftwareService, _ *config.Config, _ []swsvc.SoftwareInfo, _ bool) (bool, error) {
			return true, nil // skipped (deduped)
		})

	h := &syncSoftwareHandler{}
	note, err := h.Run(context.Background(), testSwCfg(t), taskstore.Task{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(note, "unchanged") {
		t.Errorf("note = %q, want it to report 'unchanged'", note)
	}
}

// enqueueServer is a fake Supabase that accepts agent_enqueue_software and counts calls.
func enqueueServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/rest/v1/rpc/agent_enqueue_software" {
			http.Error(w, "unexpected request "+r.Method+" "+r.URL.Path, http.StatusNotFound)
			return
		}
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"msg_id":1,"queue":"software"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// TestSyncSoftwareFn_PersistsAndSends exercises the real sync seam: it opens the
// local catalog next to cfg.Path and uploads to the (fake) backend.
func TestSyncSoftwareFn_PersistsAndSends(t *testing.T) {
	srv, calls := enqueueServer(t)
	cfg := testSwCfg(t)
	cfg.SupabaseURL = srv.URL
	svc := swsvc.NewSoftwareService()
	svc.SetSupabaseURL(srv.URL)

	// Unique list (also across -count runs) so the package-level dedup state
	// cannot skip the send.
	list := []swsvc.SoftwareInfo{{Name: "persist-and-send-" + strconv.FormatInt(time.Now().UnixNano(), 10), Source: "programs"}}
	skipped, err := syncSoftwareFn(context.Background(), svc, cfg, list, true)
	if err != nil {
		t.Fatalf("syncSoftwareFn: %v", err)
	}
	if skipped {
		t.Error("skipped = true, want the first upload to be sent")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("enqueue calls = %d, want 1", got)
	}
	dbPath := filepath.Join(filepath.Dir(cfg.Path), store.SoftwareDBName)
	if _, err := os.Stat(dbPath); err != nil {
		t.Errorf("expected catalog at %s: %v", dbPath, err)
	}
}

// TestSyncSoftwareFn_CatalogOpenFails_StillSends verifies persistence is
// best-effort: when the catalog cannot be opened the upload still happens.
func TestSyncSoftwareFn_CatalogOpenFails_StillSends(t *testing.T) {
	srv, calls := enqueueServer(t)
	cfg := testSwCfg(t)
	cfg.SupabaseURL = srv.URL
	// A directory where the database file should be makes the store unopenable.
	if err := os.Mkdir(filepath.Join(filepath.Dir(cfg.Path), store.SoftwareDBName), 0o700); err != nil {
		t.Fatal(err)
	}
	svc := swsvc.NewSoftwareService()
	svc.SetSupabaseURL(srv.URL)

	list := []swsvc.SoftwareInfo{{Name: "no-catalog-" + strconv.FormatInt(time.Now().UnixNano(), 10), Source: "programs"}}
	if _, err := syncSoftwareFn(context.Background(), svc, cfg, list, true); err != nil {
		t.Fatalf("syncSoftwareFn: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("enqueue calls = %d, want 1 (send must not depend on the catalog)", got)
	}
}

// TestGetSoftwareListFn_Default runs the real collector seam. It is skipped on
// macOS, where system_profiler makes a full scan too slow for a unit test; the
// result depends on the host, so only the call itself is exercised.
func TestGetSoftwareListFn_Default(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("real software scan is slow on macOS (system_profiler)")
	}
	list, _ := getSoftwareListFn(swsvc.NewSoftwareService())
	for _, sw := range list {
		if sw.Name == "" {
			t.Errorf("collector returned an entry with an empty name: %+v", sw)
			break
		}
	}
}
