package store

import (
	"fmt"
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

// catalogByName returns the full catalog keyed by software name, for assertions.
func catalogByName(t *testing.T, s *SoftwareStore) map[string]models.SoftwareInfo {
	t.Helper()
	all, err := s.GetAll()
	if err != nil {
		t.Fatalf("GetAll() error: %v", err)
	}
	byName := make(map[string]models.SoftwareInfo, len(all))
	for _, it := range all {
		byName[it.Name] = it
	}
	return byName
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

// TestSyncBatch_MarkUninstalled verifies the debounced uninstall path: a row that
// disappears survives every scan short of uninstallConfirmThreshold, then is demoted
// on the scan that reaches it.
func TestSyncBatch_MarkUninstalled(t *testing.T) {
	s := newTestSoftwareStore(t)
	base := time.Now().UTC().Truncate(time.Second)
	scanned := map[string]bool{"registry": true}

	initial := []models.SoftwareInfo{
		{Name: "app-a", Source: "registry"},
		{Name: "app-b", Source: "registry"},
	}
	if err := s.SyncBatch(initial, base, scanned); err != nil {
		t.Fatalf("first SyncBatch() error: %v", err)
	}

	onlyA := []models.SoftwareInfo{{Name: "app-a", Source: "registry"}}

	// Every missed scan short of the threshold must leave app-b installed (debounce).
	for miss := 1; miss < uninstallConfirmThreshold; miss++ {
		syncT := base.Add(time.Duration(miss) * time.Second)
		if err := s.SyncBatch(onlyA, syncT, scanned); err != nil {
			t.Fatalf("SyncBatch() miss %d error: %v", miss, err)
		}
		if got := catalogByName(t, s)["app-b"].Status; got != "installed" {
			t.Fatalf("app-b.Status after %d missed scan(s) = %q, want installed (debounce)", miss, got)
		}
	}

	// The scan that reaches the threshold demotes app-b.
	finalT := base.Add(time.Duration(uninstallConfirmThreshold) * time.Second)
	if err := s.SyncBatch(onlyA, finalT, scanned); err != nil {
		t.Fatalf("final SyncBatch() error: %v", err)
	}

	byName := catalogByName(t, s)
	if len(byName) != 2 {
		t.Fatalf("catalog has %d items, want 2 (both installed and uninstalled)", len(byName))
	}
	if !byName["app-a"].IsActive {
		t.Error("app-a should still be active")
	}
	if byName["app-b"].IsActive {
		t.Error("app-b should be inactive (uninstalled) after reaching the threshold")
	}
	if byName["app-b"].Status != "uninstalled" {
		t.Errorf("app-b.Status = %q, want uninstalled", byName["app-b"].Status)
	}
}

// TestSyncBatch_FailedSourceNotDemoted verifies that a source absent from
// scannedSources (its scan failed this cycle) keeps its rows installed, while a
// source that was scanned still demotes its own unseen rows. This is the core
// safety net against a transient enumeration failure wiping the catalog.
func TestSyncBatch_FailedSourceNotDemoted(t *testing.T) {
	s := newTestSoftwareStore(t)
	base := time.Now().UTC().Truncate(time.Second)

	// First cycle: both the "programs" and "microsoft_store" scans succeed.
	initial := []models.SoftwareInfo{
		{Name: "prog-a", Source: "programs"},
		{Name: "prog-b", Source: "programs"},
		{Name: "store-x", Source: "microsoft_store"},
	}
	if err := s.SyncBatch(initial, base, map[string]bool{"programs": true, "microsoft_store": true}); err != nil {
		t.Fatalf("first SyncBatch() error: %v", err)
	}

	// Later cycles: the microsoft_store scan FAILS every time (absent from
	// scannedSources) while programs returns only prog-a. Run past the threshold so
	// prog-b is demoted; store-x must stay installed because its source is never
	// scanned again (its miss counter is never even incremented).
	fresh := []models.SoftwareInfo{{Name: "prog-a", Source: "programs"}}
	for i := 1; i <= uninstallConfirmThreshold; i++ {
		syncT := base.Add(time.Duration(i) * time.Second)
		if err := s.SyncBatch(fresh, syncT, map[string]bool{"programs": true}); err != nil {
			t.Fatalf("SyncBatch() cycle %d error: %v", i, err)
		}
	}

	byName := catalogByName(t, s)
	if byName["prog-a"].Status != "installed" {
		t.Errorf("prog-a.Status = %q, want installed", byName["prog-a"].Status)
	}
	if byName["prog-b"].Status != "uninstalled" {
		t.Errorf("prog-b.Status = %q, want uninstalled (scanned source, absent past threshold)", byName["prog-b"].Status)
	}
	if byName["store-x"].Status != "installed" {
		t.Errorf("store-x.Status = %q, want installed (source never scanned again)", byName["store-x"].Status)
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

// TestSyncBatch_SingleSpuriousEmptyScanDoesNotDemote is the core robustness guard:
// a source that scans "successfully" (it IS in scannedSources) but returns zero items
// on a single cycle — a transient empty/exit-0 glitch — must not wipe the source.
// Debounce holds the rows installed until the absence is confirmed across more cycles.
func TestSyncBatch_SingleSpuriousEmptyScanDoesNotDemote(t *testing.T) {
	s := newTestSoftwareStore(t)
	base := time.Now().UTC().Truncate(time.Second)
	scanned := map[string]bool{"programs": true}

	initial := make([]models.SoftwareInfo, 0, 50)
	for i := 0; i < 50; i++ {
		initial = append(initial, models.SoftwareInfo{Name: fmt.Sprintf("app-%02d", i), Source: "programs"})
	}
	if err := s.SyncBatch(initial, base, scanned); err != nil {
		t.Fatalf("seed SyncBatch() error: %v", err)
	}

	// The source scans successfully but returns nothing this one cycle.
	if err := s.SyncBatch(nil, base.Add(time.Second), scanned); err != nil {
		t.Fatalf("empty-scan SyncBatch() error: %v", err)
	}

	for _, it := range catalogByName(t, s) {
		if it.Status != "installed" {
			t.Fatalf("%s demoted after a single spurious empty scan; want every row preserved", it.Name)
		}
	}
}

// TestSyncBatch_ReappearanceResetsMissCounter verifies that software which flaps
// (missing, then present again) never accumulates enough CONSECUTIVE misses to be
// demoted: each reappearance resets the counter.
func TestSyncBatch_ReappearanceResetsMissCounter(t *testing.T) {
	s := newTestSoftwareStore(t)
	base := time.Now().UTC().Truncate(time.Second)
	scanned := map[string]bool{"registry": true}

	full := []models.SoftwareInfo{
		{Name: "app-a", Source: "registry"},
		{Name: "app-b", Source: "registry"},
	}
	onlyA := []models.SoftwareInfo{{Name: "app-a", Source: "registry"}}
	if err := s.SyncBatch(full, base, scanned); err != nil {
		t.Fatalf("seed SyncBatch() error: %v", err)
	}

	cycle := 0
	next := func() time.Time {
		cycle++
		return base.Add(time.Duration(cycle) * time.Second)
	}
	// Drive app-b to one short of the threshold...
	for miss := 1; miss < uninstallConfirmThreshold; miss++ {
		if err := s.SyncBatch(onlyA, next(), scanned); err != nil {
			t.Fatalf("pre-reset SyncBatch() error: %v", err)
		}
	}
	// ...let it reappear (resets the counter)...
	if err := s.SyncBatch(full, next(), scanned); err != nil {
		t.Fatalf("reappearance SyncBatch() error: %v", err)
	}
	// ...then go missing again for another (threshold-1) cycles. Without the reset the
	// total misses would reach/exceed the threshold; with it, app-b stays installed.
	for miss := 1; miss < uninstallConfirmThreshold; miss++ {
		if err := s.SyncBatch(onlyA, next(), scanned); err != nil {
			t.Fatalf("post-reset SyncBatch() error: %v", err)
		}
	}

	if got := catalogByName(t, s)["app-b"].Status; got != "installed" {
		t.Errorf("app-b.Status = %q, want installed (reappearance must reset the miss counter)", got)
	}
}

// TestSyncBatch_MultipleSourcesFailSimultaneously extends the single-source guard:
// when two sources fail in the same cycle while a third succeeds, neither failed
// source is demoted even after several cycles.
func TestSyncBatch_MultipleSourcesFailSimultaneously(t *testing.T) {
	s := newTestSoftwareStore(t)
	base := time.Now().UTC().Truncate(time.Second)

	initial := []models.SoftwareInfo{
		{Name: "deb-1", Source: "deb_packages"},
		{Name: "snap-1", Source: "snap_packages"},
		{Name: "flat-1", Source: "flatpak_packages"},
	}
	allSources := map[string]bool{"deb_packages": true, "snap_packages": true, "flatpak_packages": true}
	if err := s.SyncBatch(initial, base, allSources); err != nil {
		t.Fatalf("seed SyncBatch() error: %v", err)
	}

	// deb keeps succeeding; snap and flatpak both fail every cycle.
	debOnly := []models.SoftwareInfo{{Name: "deb-1", Source: "deb_packages"}}
	for i := 1; i <= uninstallConfirmThreshold+1; i++ {
		syncT := base.Add(time.Duration(i) * time.Second)
		if err := s.SyncBatch(debOnly, syncT, map[string]bool{"deb_packages": true}); err != nil {
			t.Fatalf("SyncBatch() cycle %d error: %v", i, err)
		}
	}

	byName := catalogByName(t, s)
	for _, name := range []string{"snap-1", "flat-1"} {
		if byName[name].Status != "installed" {
			t.Errorf("%s.Status = %q, want installed (its source failed every cycle)", name, byName[name].Status)
		}
	}
	if byName["deb-1"].Status != "installed" {
		t.Errorf("deb-1.Status = %q, want installed (seen every cycle)", byName["deb-1"].Status)
	}
}

// TestSyncBatch_PreservesRealInstallDate verifies that the collector's real install
// date is stored on first insert and never overwritten on a later re-upsert, while a
// missing install date falls back to the sync time.
func TestSyncBatch_PreservesRealInstallDate(t *testing.T) {
	s := newTestSoftwareStore(t)
	syncT := time.Now().UTC().Truncate(time.Second)
	installDate := "2020-01-02T03:04:05Z"

	items := []models.SoftwareInfo{
		{Name: "old-app", Source: "rpm_packages", FirstSeenAt: installDate},
		{Name: "no-date", Source: "rpm_packages"},
	}
	if err := s.SyncBatch(items, syncT, map[string]bool{"rpm_packages": true}); err != nil {
		t.Fatalf("first SyncBatch() error: %v", err)
	}

	byName := catalogByName(t, s)
	if byName["old-app"].FirstSeenAt != installDate {
		t.Errorf("old-app.FirstSeenAt = %q, want preserved install date %q", byName["old-app"].FirstSeenAt, installDate)
	}
	wantFallback := syncT.Format(time.RFC3339)
	if byName["no-date"].FirstSeenAt != wantFallback {
		t.Errorf("no-date.FirstSeenAt = %q, want sync-time fallback %q", byName["no-date"].FirstSeenAt, wantFallback)
	}

	// A later cycle reporting a different first-seen must not overwrite the stored one.
	later := syncT.Add(time.Hour)
	update := []models.SoftwareInfo{
		{Name: "old-app", Source: "rpm_packages", FirstSeenAt: "2099-12-31T00:00:00Z", InstalledVersion: "2.0"},
	}
	if err := s.SyncBatch(update, later, map[string]bool{"rpm_packages": true}); err != nil {
		t.Fatalf("second SyncBatch() error: %v", err)
	}
	byName = catalogByName(t, s)
	if byName["old-app"].FirstSeenAt != installDate {
		t.Errorf("old-app.FirstSeenAt after re-upsert = %q, want original %q (must not change on update)", byName["old-app"].FirstSeenAt, installDate)
	}
	if byName["old-app"].InstalledVersion != "2.0" {
		t.Errorf("old-app.InstalledVersion = %q, want updated 2.0", byName["old-app"].InstalledVersion)
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
