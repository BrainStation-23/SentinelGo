package store_test

import (
	"testing"

	"sentinelgo/internal/models"
	"sentinelgo/internal/store"
)

func openSoftwareStoreInMemory(t *testing.T) *store.SoftwareStore {
	t.Helper()
	s, err := store.NewSoftwareStore(":memory:")
	if err != nil {
		t.Fatalf("NewSoftwareStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSoftwareStore_UpsertAndGetAll(t *testing.T) {
	s := openSoftwareStoreInMemory(t)

	items := []models.SoftwareInfo{
		{Name: "Google Chrome", Source: "programs", Type: "programs", InstalledVersion: "120.0", FilePath: `C:\Program Files\Chrome`},
		{Name: "uBlock Origin", Source: "chrome_extensions", Type: "chrome_extensions", InstalledVersion: "1.5"},
	}
	if err := s.Upsert("agent-1", items); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := s.GetAll("agent-1")
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("GetAll returned %d items, want 2", len(got))
	}
}

// Same name across different sources must not collide (unique key is name+source).
func TestSoftwareStore_SameNameDifferentSource(t *testing.T) {
	s := openSoftwareStoreInMemory(t)

	items := []models.SoftwareInfo{
		{Name: "node", Source: "deb_packages"},
		{Name: "node", Source: "snap_packages"},
	}
	if err := s.Upsert("agent-1", items); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	got, _ := s.GetAll("agent-1")
	if len(got) != 2 {
		t.Fatalf("want 2 rows for same name + distinct source, got %d", len(got))
	}
}

func TestSoftwareStore_UpsertPreservesFirstSeenAt(t *testing.T) {
	s := openSoftwareStoreInMemory(t)

	original := []models.SoftwareInfo{
		{Name: "VS Code", Source: "programs", InstalledVersion: "1.80", FirstSeenAt: "2024-01-01T00:00:00Z"},
	}
	if err := s.Upsert("agent-1", original); err != nil {
		t.Fatalf("first Upsert: %v", err)
	}

	updated := []models.SoftwareInfo{
		{Name: "VS Code", Source: "programs", InstalledVersion: "1.95", FirstSeenAt: "2024-06-01T00:00:00Z"},
	}
	if err := s.Upsert("agent-1", updated); err != nil {
		t.Fatalf("second Upsert: %v", err)
	}

	got, _ := s.GetAll("agent-1")
	if len(got) != 1 {
		t.Fatalf("GetAll returned %d items, want 1", len(got))
	}
	if got[0].InstalledVersion != "1.95" {
		t.Errorf("InstalledVersion = %q, want 1.95 (should update)", got[0].InstalledVersion)
	}
	if got[0].FirstSeenAt != "2024-01-01T00:00:00Z" {
		t.Errorf("FirstSeenAt = %q, want original (must not overwrite)", got[0].FirstSeenAt)
	}
}

func TestSoftwareStore_AgentIsolation(t *testing.T) {
	s := openSoftwareStoreInMemory(t)

	_ = s.Upsert("agent-A", []models.SoftwareInfo{{Name: "app-a", Source: "programs"}})
	_ = s.Upsert("agent-B", []models.SoftwareInfo{{Name: "app-b", Source: "programs"}})

	gotA, _ := s.GetAll("agent-A")
	gotB, _ := s.GetAll("agent-B")
	if len(gotA) != 1 || gotA[0].Name != "app-a" {
		t.Errorf("agent-A: got %+v", gotA)
	}
	if len(gotB) != 1 || gotB[0].Name != "app-b" {
		t.Errorf("agent-B: got %+v", gotB)
	}
}

func TestSoftwareStore_DeleteNotIn(t *testing.T) {
	s := openSoftwareStoreInMemory(t)

	items := []models.SoftwareInfo{
		{Name: "alpha", Source: "programs"},
		{Name: "beta", Source: "programs"},
		{Name: "gamma", Source: "programs"},
	}
	if err := s.Upsert("agent-1", items); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	keep := []string{"alpha\x00programs", "beta\x00programs"}
	if err := s.DeleteNotIn("agent-1", keep); err != nil {
		t.Fatalf("DeleteNotIn: %v", err)
	}

	got, _ := s.GetAll("agent-1")
	if len(got) != 2 {
		t.Fatalf("want 2 after prune, got %d", len(got))
	}
	for _, sw := range got {
		if sw.Name == "gamma" {
			t.Error("gamma should have been pruned")
		}
	}
}

func TestSoftwareStore_DeleteNotInEmptyWipesAgentOnly(t *testing.T) {
	s := openSoftwareStoreInMemory(t)

	_ = s.Upsert("agent-1", []models.SoftwareInfo{{Name: "x", Source: "programs"}})
	_ = s.Upsert("agent-2", []models.SoftwareInfo{{Name: "y", Source: "programs"}})

	if err := s.DeleteNotIn("agent-1", nil); err != nil {
		t.Fatalf("DeleteNotIn(nil): %v", err)
	}
	got1, _ := s.GetAll("agent-1")
	got2, _ := s.GetAll("agent-2")
	if len(got1) != 0 {
		t.Errorf("agent-1: want 0 after empty prune, got %d", len(got1))
	}
	if len(got2) != 1 {
		t.Errorf("agent-2: want 1 untouched, got %d", len(got2))
	}
}

func TestSoftwareStore_UpsertEmpty(t *testing.T) {
	s := openSoftwareStoreInMemory(t)
	if err := s.Upsert("agent-1", nil); err != nil {
		t.Fatalf("Upsert(nil): %v", err)
	}
	got, _ := s.GetAll("agent-1")
	if len(got) != 0 {
		t.Errorf("want 0, got %d", len(got))
	}
}
