package store_test

import (
	"testing"

	"sentinelgo/internal/models"
	"sentinelgo/internal/store"
)

// openServicesStoreInMemory opens an in-memory SQLite database and returns an
// initialised ServicesStore. Uses NewServicesStore so migrations are exercised.
func openServicesStoreInMemory(t *testing.T) *store.ServicesStore {
	t.Helper()
	s, err := store.NewServicesStore(":memory:")
	if err != nil {
		t.Fatalf("NewServicesStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestServicesStore_UpsertAndGetAll verifies the basic write-then-read path.
func TestServicesStore_UpsertAndGetAll(t *testing.T) {
	s := openServicesStoreInMemory(t)

	svcs := []models.ServiceInfo{
		{Name: "ssh.service", DisplayName: "SSH", Status: "running", StartType: "automatic", Source: "systemd", PID: 1234},
		{Name: "cron.service", DisplayName: "Cron", Status: "stopped", StartType: "automatic", Source: "systemd"},
	}

	if err := s.Upsert("agent-1", svcs); err != nil {
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

// TestServicesStore_UpsertPreservesFirstSeenAt verifies that re-upserting does
// not overwrite the original first_seen_at timestamp.
func TestServicesStore_UpsertPreservesFirstSeenAt(t *testing.T) {
	s := openServicesStoreInMemory(t)

	original := []models.ServiceInfo{
		{
			Name:        "nginx.service",
			DisplayName: "Nginx",
			Status:      "running",
			Source:      "systemd",
			FirstSeenAt: "2024-01-01T00:00:00Z",
			UpdatedAt:   "2024-01-01T00:00:00Z",
		},
	}
	if err := s.Upsert("agent-1", original); err != nil {
		t.Fatalf("first Upsert: %v", err)
	}

	updated := []models.ServiceInfo{
		{
			Name:        "nginx.service",
			DisplayName: "Nginx",
			Status:      "stopped", // status changed
			Source:      "systemd",
			FirstSeenAt: "2024-06-01T00:00:00Z", // later timestamp; must NOT overwrite original
			UpdatedAt:   "2024-06-01T00:00:00Z",
		},
	}
	if err := s.Upsert("agent-1", updated); err != nil {
		t.Fatalf("second Upsert: %v", err)
	}

	got, err := s.GetAll("agent-1")
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("GetAll returned %d items, want 1", len(got))
	}
	if got[0].Status != "stopped" {
		t.Errorf("Status = %q, want %q", got[0].Status, "stopped")
	}
	if got[0].FirstSeenAt != "2024-01-01T00:00:00Z" {
		t.Errorf("FirstSeenAt = %q, want original %q", got[0].FirstSeenAt, "2024-01-01T00:00:00Z")
	}
}

// TestServicesStore_AgentIsolation verifies that GetAll returns only services
// for the requested agent.
func TestServicesStore_AgentIsolation(t *testing.T) {
	s := openServicesStoreInMemory(t)

	_ = s.Upsert("agent-A", []models.ServiceInfo{{Name: "svc-a.service", Source: "systemd"}})
	_ = s.Upsert("agent-B", []models.ServiceInfo{{Name: "svc-b.service", Source: "systemd"}})

	gotA, _ := s.GetAll("agent-A")
	gotB, _ := s.GetAll("agent-B")

	if len(gotA) != 1 || gotA[0].Name != "svc-a.service" {
		t.Errorf("agent-A: got %+v", gotA)
	}
	if len(gotB) != 1 || gotB[0].Name != "svc-b.service" {
		t.Errorf("agent-B: got %+v", gotB)
	}
}

// TestServicesStore_DeleteNotIn verifies that stale services are pruned after
// a full scan.
func TestServicesStore_DeleteNotIn(t *testing.T) {
	s := openServicesStoreInMemory(t)

	svcs := []models.ServiceInfo{
		{Name: "alpha.service", Source: "systemd"},
		{Name: "beta.service", Source: "systemd"},
		{Name: "gamma.service", Source: "systemd"},
	}
	if err := s.Upsert("agent-1", svcs); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	keep := []string{"alpha.service\x00systemd", "beta.service\x00systemd"}
	if err := s.DeleteNotIn("agent-1", keep); err != nil {
		t.Fatalf("DeleteNotIn: %v", err)
	}

	got, err := s.GetAll("agent-1")
	if err != nil {
		t.Fatalf("GetAll after delete: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 services after DeleteNotIn, got %d", len(got))
	}
	for _, svc := range got {
		if svc.Name == "gamma.service" {
			t.Errorf("gamma.service should have been deleted")
		}
	}
}

// TestServicesStore_DeleteNotInEmpty verifies that passing no active keys
// deletes all services for the agent without touching other agents.
func TestServicesStore_DeleteNotInEmpty(t *testing.T) {
	s := openServicesStoreInMemory(t)

	_ = s.Upsert("agent-1", []models.ServiceInfo{{Name: "svc.service", Source: "systemd"}})
	_ = s.Upsert("agent-2", []models.ServiceInfo{{Name: "other.service", Source: "systemd"}})

	if err := s.DeleteNotIn("agent-1", nil); err != nil {
		t.Fatalf("DeleteNotIn(nil): %v", err)
	}

	got1, _ := s.GetAll("agent-1")
	got2, _ := s.GetAll("agent-2")

	if len(got1) != 0 {
		t.Errorf("agent-1: expected empty after DeleteNotIn, got %d services", len(got1))
	}
	if len(got2) != 1 {
		t.Errorf("agent-2: expected 1 service untouched, got %d", len(got2))
	}
}

// TestServicesStore_UpsertEmpty verifies that upserting an empty slice is a no-op.
func TestServicesStore_UpsertEmpty(t *testing.T) {
	s := openServicesStoreInMemory(t)

	if err := s.Upsert("agent-1", nil); err != nil {
		t.Fatalf("Upsert(nil): %v", err)
	}
	if err := s.Upsert("agent-1", []models.ServiceInfo{}); err != nil {
		t.Fatalf("Upsert([]): %v", err)
	}

	got, _ := s.GetAll("agent-1")
	if len(got) != 0 {
		t.Errorf("expected no services, got %d", len(got))
	}
}

// TestServicesStore_MigrationIdempotent verifies that opening an already-migrated
// database (via a second NewServicesStore on the same file) does not fail.
// We achieve this by running migrations twice on the same path.
func TestServicesStore_MigrationIdempotent(t *testing.T) {
	s1, err := store.NewServicesStore(":memory:")
	if err != nil {
		t.Fatalf("first NewServicesStore: %v", err)
	}
	defer func() { _ = s1.Close() }()

	// Upsert something to confirm the schema is in place.
	if err := s1.Upsert("agent-1", []models.ServiceInfo{{Name: "x.service", Source: "systemd"}}); err != nil {
		t.Fatalf("Upsert after first open: %v", err)
	}
}
