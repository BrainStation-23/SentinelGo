package store_test

import (
	"testing"

	"sentinelgo/internal/models"
)

// ── GetHashCache ──────────────────────────────────────────────────────────────

// TestGetHashCache_Empty verifies an empty map is returned when no rows have a
// sha256_hash.
func TestGetHashCache_Empty(t *testing.T) {
	s := openSoftwareStoreInMemory(t)

	_ = s.Upsert("agent-1", []models.SoftwareInfo{
		{Name: "nohash-app", Source: "programs"},
	})

	cache, err := s.GetHashCache("agent-1")
	if err != nil {
		t.Fatalf("GetHashCache: %v", err)
	}
	if len(cache) != 0 {
		t.Errorf("expected empty cache when no hashes stored, got %d entries", len(cache))
	}
}

// TestGetHashCache_ReturnsStoredHashes verifies that only rows with a non-empty
// sha256_hash appear in the cache.
func TestGetHashCache_ReturnsStoredHashes(t *testing.T) {
	s := openSoftwareStoreInMemory(t)

	items := []models.SoftwareInfo{
		{Name: "hashed-app", Source: "programs", SHA256Hash: "abc123", FilePath: `C:\app.exe`},
		{Name: "no-hash-app", Source: "programs"},
	}
	if err := s.Upsert("agent-1", items); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	cache, err := s.GetHashCache("agent-1")
	if err != nil {
		t.Fatalf("GetHashCache: %v", err)
	}
	if len(cache) != 1 {
		t.Fatalf("expected 1 cache entry, got %d", len(cache))
	}
	key := "hashed-app\x00programs"
	if got := cache[key]; got != "abc123" {
		t.Errorf("cache[%q] = %q, want %q", key, got, "abc123")
	}
}

// TestGetHashCache_AgentIsolation verifies cache lookups respect agent_id
// boundaries.
func TestGetHashCache_AgentIsolation(t *testing.T) {
	s := openSoftwareStoreInMemory(t)

	_ = s.Upsert("agent-A", []models.SoftwareInfo{
		{Name: "app", Source: "programs", SHA256Hash: "hashA"},
	})
	_ = s.Upsert("agent-B", []models.SoftwareInfo{
		{Name: "app", Source: "programs", SHA256Hash: "hashB"},
	})

	cacheA, _ := s.GetHashCache("agent-A")
	cacheB, _ := s.GetHashCache("agent-B")

	if cacheA["app\x00programs"] != "hashA" {
		t.Errorf("agent-A cache = %q, want hashA", cacheA["app\x00programs"])
	}
	if cacheB["app\x00programs"] != "hashB" {
		t.Errorf("agent-B cache = %q, want hashB", cacheB["app\x00programs"])
	}
}

// ── Upsert CASE WHEN hash/publisher preservation ──────────────────────────────

// TestSoftwareStore_UpsertPreservesHashWhenUpdateIsEmpty verifies that a cached
// sha256_hash is not overwritten when a subsequent upsert sends an empty hash
// (e.g. the enrichment pass skipped the file due to a transient error).
func TestSoftwareStore_UpsertPreservesHashWhenUpdateIsEmpty(t *testing.T) {
	s := openSoftwareStoreInMemory(t)

	// First upsert: hash is populated.
	if err := s.Upsert("agent-1", []models.SoftwareInfo{
		{Name: "VS Code", Source: "programs", SHA256Hash: "deadbeef"},
	}); err != nil {
		t.Fatalf("first Upsert: %v", err)
	}

	// Second upsert: hash is empty (enrichment skipped this file).
	if err := s.Upsert("agent-1", []models.SoftwareInfo{
		{Name: "VS Code", Source: "programs", SHA256Hash: ""},
	}); err != nil {
		t.Fatalf("second Upsert: %v", err)
	}

	got, _ := s.GetAll("agent-1")
	if len(got) != 1 {
		t.Fatalf("GetAll returned %d items, want 1", len(got))
	}
	if got[0].SHA256Hash != "deadbeef" {
		t.Errorf("SHA256Hash = %q after empty-hash upsert, want %q (must be preserved)",
			got[0].SHA256Hash, "deadbeef")
	}
}

// TestSoftwareStore_UpsertOverwritesHashWhenNewHashProvided verifies that a
// non-empty incoming hash does replace the previously stored value.
func TestSoftwareStore_UpsertOverwritesHashWhenNewHashProvided(t *testing.T) {
	s := openSoftwareStoreInMemory(t)

	_ = s.Upsert("agent-1", []models.SoftwareInfo{
		{Name: "App", Source: "programs", SHA256Hash: "oldhash"},
	})
	_ = s.Upsert("agent-1", []models.SoftwareInfo{
		{Name: "App", Source: "programs", SHA256Hash: "newhash"},
	})

	got, _ := s.GetAll("agent-1")
	if got[0].SHA256Hash != "newhash" {
		t.Errorf("SHA256Hash = %q, want newhash", got[0].SHA256Hash)
	}
}

// TestSoftwareStore_UpsertPreservesPublisherWhenUpdateIsEmpty mirrors the hash
// preservation test but for the Publisher field.
func TestSoftwareStore_UpsertPreservesPublisherWhenUpdateIsEmpty(t *testing.T) {
	s := openSoftwareStoreInMemory(t)

	_ = s.Upsert("agent-1", []models.SoftwareInfo{
		{Name: "Chrome", Source: "programs", Publisher: "Google LLC"},
	})
	_ = s.Upsert("agent-1", []models.SoftwareInfo{
		{Name: "Chrome", Source: "programs", Publisher: ""},
	})

	got, _ := s.GetAll("agent-1")
	if got[0].Publisher != "Google LLC" {
		t.Errorf("Publisher = %q after empty update, want %q (must be preserved)",
			got[0].Publisher, "Google LLC")
	}
}

// TestSoftwareStore_UpsertAndGetAll_HashPublisher verifies the full round-trip:
// upsert items with hash+publisher and read them back via GetAll.
func TestSoftwareStore_UpsertAndGetAll_HashPublisher(t *testing.T) {
	s := openSoftwareStoreInMemory(t)

	items := []models.SoftwareInfo{
		{
			Name:       "Slack",
			Source:     "programs",
			SHA256Hash: "cafebabe",
			Publisher:  "Slack Technologies",
			FilePath:   `C:\Program Files\Slack\slack.exe`,
		},
		{
			Name:   "uBlock Origin",
			Source: "chrome_extensions",
			// No FilePath → no hash expected
		},
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

	// GetAll orders by source then name; chrome_extensions < programs alphabetically.
	ext := got[0]
	slack := got[1]

	if ext.Name != "uBlock Origin" {
		t.Errorf("got[0].Name = %q, want uBlock Origin", ext.Name)
	}
	if ext.SHA256Hash != "" {
		t.Errorf("extension SHA256Hash = %q, want empty", ext.SHA256Hash)
	}

	if slack.Name != "Slack" {
		t.Errorf("got[1].Name = %q, want Slack", slack.Name)
	}
	if slack.SHA256Hash != "cafebabe" {
		t.Errorf("Slack SHA256Hash = %q, want cafebabe", slack.SHA256Hash)
	}
	if slack.Publisher != "Slack Technologies" {
		t.Errorf("Slack Publisher = %q, want Slack Technologies", slack.Publisher)
	}
}
