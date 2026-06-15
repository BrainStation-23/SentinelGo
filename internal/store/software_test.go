package store

import (
	"path/filepath"
	"testing"
	"time"

	"sentinelgo/internal/models"
)

func softwareDBPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "software_test.db")
}

func newTestSoftwareStore(t *testing.T) *SoftwareStore {
	t.Helper()
	s, err := NewSoftwareStore(softwareDBPath(t))
	if err != nil {
		t.Fatalf("NewSoftwareStore() failed: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestNewSoftwareStore(t *testing.T) {
	s := newTestSoftwareStore(t)
	if s == nil {
		t.Fatal("NewSoftwareStore() returned nil")
	}
}

func TestNewSoftwareStore_IdempotentMigration(t *testing.T) {
	path := softwareDBPath(t)

	s1, err := NewSoftwareStore(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	_ = s1.Close()

	s2, err := NewSoftwareStore(path)
	if err != nil {
		t.Fatalf("second open (idempotent migration): %v", err)
	}
	_ = s2.Close()
}

func TestSyncBatch_Empty(t *testing.T) {
	s := newTestSoftwareStore(t)
	if err := s.SyncBatch(nil, time.Now(), nil); err != nil {
		t.Fatalf("SyncBatch(nil) error: %v", err)
	}
	items, err := s.GetAll()
	if err != nil {
		t.Fatalf("GetAll() error: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("GetAll() after empty sync = %d items, want 0", len(items))
	}
}

func TestSyncBatch_Insert(t *testing.T) {
	s := newTestSoftwareStore(t)
	now := time.Now().UTC().Truncate(time.Second)

	items := []models.SoftwareInfo{
		{Name: "app-a", Source: "registry", Type: "application", InstalledVersion: "1.0"},
		{Name: "app-b", Source: "registry", Type: "application", InstalledVersion: "2.0"},
	}
	if err := s.SyncBatch(items, now, map[string]bool{"registry": true}); err != nil {
		t.Fatalf("SyncBatch() error: %v", err)
	}

	got, err := s.GetAll()
	if err != nil {
		t.Fatalf("GetAll() error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("GetAll() = %d items, want 2", len(got))
	}
	// Results are ordered by name ASC
	if got[0].Name != "app-a" {
		t.Errorf("got[0].Name = %q, want %q", got[0].Name, "app-a")
	}
	if got[1].Name != "app-b" {
		t.Errorf("got[1].Name = %q, want %q", got[1].Name, "app-b")
	}
	if !got[0].IsActive {
		t.Error("got[0].IsActive should be true for a just-synced app")
	}
	if got[0].Status != "installed" {
		t.Errorf("got[0].Status = %q, want %q", got[0].Status, "installed")
	}
}

func TestSyncBatch_MarkUninstalled(t *testing.T) {
	s := newTestSoftwareStore(t)

	t1 := time.Now().UTC().Truncate(time.Second)
	t2 := t1.Add(time.Second)

	initial := []models.SoftwareInfo{
		{Name: "app-a", Source: "registry"},
		{Name: "app-b", Source: "registry"},
	}
	if err := s.SyncBatch(initial, t1, map[string]bool{"registry": true}); err != nil {
		t.Fatalf("first SyncBatch() error: %v", err)
	}

	// Second sync sees only app-a; app-b should be marked uninstalled.
	onlyA := []models.SoftwareInfo{
		{Name: "app-a", Source: "registry"},
	}
	if err := s.SyncBatch(onlyA, t2, map[string]bool{"registry": true}); err != nil {
		t.Fatalf("second SyncBatch() error: %v", err)
	}

	all, err := s.GetAll()
	if err != nil {
		t.Fatalf("GetAll() error: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("GetAll() = %d items, want 2 (both installed and uninstalled)", len(all))
	}

	byName := make(map[string]models.SoftwareInfo, 2)
	for _, item := range all {
		byName[item.Name] = item
	}

	if !byName["app-a"].IsActive {
		t.Error("app-a should still be active after second sync")
	}
	if byName["app-b"].IsActive {
		t.Error("app-b should be marked inactive (uninstalled)")
	}
	if byName["app-b"].Status != "uninstalled" {
		t.Errorf("app-b.Status = %q, want %q", byName["app-b"].Status, "uninstalled")
	}
}

// TestSyncBatch_FailedSourceNotDemoted verifies that a source absent from
// scannedSources (its scan failed this cycle) keeps its rows installed, while a
// source that was scanned still demotes its own unseen rows. This is the core
// safety net against a transient enumeration failure wiping the catalog.
func TestSyncBatch_FailedSourceNotDemoted(t *testing.T) {
	s := newTestSoftwareStore(t)

	t1 := time.Now().UTC().Truncate(time.Second)
	t2 := t1.Add(time.Second)

	// First cycle: both the "programs" and "microsoft_store" scans succeed.
	initial := []models.SoftwareInfo{
		{Name: "prog-a", Source: "programs"},
		{Name: "prog-b", Source: "programs"},
		{Name: "store-x", Source: "microsoft_store"},
	}
	if err := s.SyncBatch(initial, t1, map[string]bool{"programs": true, "microsoft_store": true}); err != nil {
		t.Fatalf("first SyncBatch() error: %v", err)
	}

	// Second cycle: the microsoft_store scan FAILED (not in scannedSources) and the
	// programs scan returned only prog-a. prog-b must be demoted; store-x must be
	// preserved because its source was never scanned this cycle.
	fresh := []models.SoftwareInfo{
		{Name: "prog-a", Source: "programs"},
	}
	if err := s.SyncBatch(fresh, t2, map[string]bool{"programs": true}); err != nil {
		t.Fatalf("second SyncBatch() error: %v", err)
	}

	byName := make(map[string]models.SoftwareInfo)
	all, err := s.GetAll()
	if err != nil {
		t.Fatalf("GetAll() error: %v", err)
	}
	for _, item := range all {
		byName[item.Name] = item
	}

	if byName["prog-a"].Status != "installed" {
		t.Errorf("prog-a.Status = %q, want installed", byName["prog-a"].Status)
	}
	if byName["prog-b"].Status != "uninstalled" {
		t.Errorf("prog-b.Status = %q, want uninstalled (scanned source, not seen)", byName["prog-b"].Status)
	}
	if byName["store-x"].Status != "installed" {
		t.Errorf("store-x.Status = %q, want installed (source not scanned this cycle)", byName["store-x"].Status)
	}
}

// TestSyncBatch_EmptyScannedSourcesPreservesCatalog verifies the regression guard:
// a cycle where no source scanned successfully (empty scannedSources, empty items)
// must not demote anything.
func TestSyncBatch_EmptyScannedSourcesPreservesCatalog(t *testing.T) {
	s := newTestSoftwareStore(t)

	t1 := time.Now().UTC().Truncate(time.Second)
	t2 := t1.Add(time.Second)

	initial := []models.SoftwareInfo{
		{Name: "prog-a", Source: "programs"},
		{Name: "prog-b", Source: "programs"},
	}
	if err := s.SyncBatch(initial, t1, map[string]bool{"programs": true}); err != nil {
		t.Fatalf("first SyncBatch() error: %v", err)
	}

	// Total scan failure: no items, no scanned sources.
	if err := s.SyncBatch(nil, t2, nil); err != nil {
		t.Fatalf("second SyncBatch() error: %v", err)
	}

	all, err := s.GetAll()
	if err != nil {
		t.Fatalf("GetAll() error: %v", err)
	}
	for _, item := range all {
		if item.Status != "installed" {
			t.Errorf("%s.Status = %q, want installed (catalog must be preserved on total scan failure)", item.Name, item.Status)
		}
	}
}

func TestQueueSync_HasPendingSync_ClearSync(t *testing.T) {
	s := newTestSoftwareStore(t)

	pending, err := s.HasPendingSync()
	if err != nil {
		t.Fatalf("HasPendingSync() error: %v", err)
	}
	if pending {
		t.Error("HasPendingSync() = true before any QueueSync, want false")
	}

	if err := s.QueueSync(); err != nil {
		t.Fatalf("QueueSync() error: %v", err)
	}

	pending, err = s.HasPendingSync()
	if err != nil {
		t.Fatalf("HasPendingSync() after QueueSync error: %v", err)
	}
	if !pending {
		t.Error("HasPendingSync() = false after QueueSync, want true")
	}

	if err := s.ClearSync(); err != nil {
		t.Fatalf("ClearSync() error: %v", err)
	}

	pending, err = s.HasPendingSync()
	if err != nil {
		t.Fatalf("HasPendingSync() after ClearSync error: %v", err)
	}
	if pending {
		t.Error("HasPendingSync() = true after ClearSync, want false")
	}
}

func TestGetAll_Empty(t *testing.T) {
	s := newTestSoftwareStore(t)
	items, err := s.GetAll()
	if err != nil {
		t.Fatalf("GetAll() error: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("GetAll() on empty store = %d items, want 0", len(items))
	}
}

func TestSoftwareStore_Close(t *testing.T) {
	s, err := NewSoftwareStore(softwareDBPath(t))
	if err != nil {
		t.Fatalf("NewSoftwareStore() error: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
	// After close, queries must fail.
	_, err = s.GetAll()
	if err == nil {
		t.Error("GetAll() after Close() should return an error, got nil")
	}
}
