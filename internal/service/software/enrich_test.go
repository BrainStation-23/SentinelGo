package software_test

import (
	"errors"
	"testing"

	"sentinelgo/internal/service/software"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// mockHasher returns a HashFunc-compatible func that always returns the given
// hash and error.
func mockHasher(hash string, err error) func(string) (string, error) {
	return func(_ string) (string, error) {
		return hash, err
	}
}

// callCountingHasher returns a func that counts how many times it was called
// and always returns "fixed-hash".
func callCountingHasher(calls *int) func(string) (string, error) {
	return func(_ string) (string, error) {
		*calls++
		return "fixed-hash", nil
	}
}

// ── EnrichWithHash ────────────────────────────────────────────────────────────

// TestEnrichWithHash_EmptyFilePath verifies that items without a FilePath are
// skipped entirely — the hash function must not be called and SHA256Hash stays
// empty.
func TestEnrichWithHash_EmptyFilePath(t *testing.T) {
	calls := 0
	items := []software.SoftwareInfo{
		{Name: "deb-pkg", Source: "deb_packages", FilePath: ""},
	}

	result := software.EnrichWithHash(items, nil, callCountingHasher(&calls))

	if calls != 0 {
		t.Errorf("computeHash called %d times for item with no FilePath, want 0", calls)
	}
	if result[0].SHA256Hash != "" {
		t.Errorf("SHA256Hash = %q, want empty for item with no FilePath", result[0].SHA256Hash)
	}
}

// TestEnrichWithHash_CacheHit verifies that a cached hash is reused and
// computeHash is NOT called.
func TestEnrichWithHash_CacheHit(t *testing.T) {
	calls := 0
	cache := map[string]string{
		"VS Code\x00programs": "deadbeef",
	}
	items := []software.SoftwareInfo{
		{Name: "VS Code", Source: "programs", FilePath: `C:\app\code.exe`},
	}

	result := software.EnrichWithHash(items, cache, callCountingHasher(&calls))

	if calls != 0 {
		t.Errorf("computeHash called %d times on cache hit, want 0", calls)
	}
	if result[0].SHA256Hash != "deadbeef" {
		t.Errorf("SHA256Hash = %q, want deadbeef (from cache)", result[0].SHA256Hash)
	}
}

// TestEnrichWithHash_CacheMiss verifies that when there's no cached hash,
// computeHash is called and the result is stored.
func TestEnrichWithHash_CacheMiss(t *testing.T) {
	items := []software.SoftwareInfo{
		{Name: "Slack", Source: "programs", FilePath: `/Applications/Slack.app`},
	}

	result := software.EnrichWithHash(items, map[string]string{}, mockHasher("abc123", nil))

	if result[0].SHA256Hash != "abc123" {
		t.Errorf("SHA256Hash = %q, want abc123", result[0].SHA256Hash)
	}
}

// TestEnrichWithHash_HashError verifies that a computeHash error for one item
// does not affect the rest: the failing item's SHA256Hash stays empty, other
// items are still enriched.
func TestEnrichWithHash_HashError(t *testing.T) {
	hashErr := errors.New("permission denied")
	callCount := 0
	hashFn := func(path string) (string, error) {
		callCount++
		if path == "/bad/path" {
			return "", hashErr
		}
		return "goodhash", nil
	}

	items := []software.SoftwareInfo{
		{Name: "Bad App", Source: "programs", FilePath: "/bad/path"},
		{Name: "Good App", Source: "programs", FilePath: "/good/path"},
	}

	result := software.EnrichWithHash(items, map[string]string{}, hashFn)

	if result[0].SHA256Hash != "" {
		t.Errorf("Bad App SHA256Hash = %q, want empty on hash error", result[0].SHA256Hash)
	}
	if result[1].SHA256Hash != "goodhash" {
		t.Errorf("Good App SHA256Hash = %q, want goodhash", result[1].SHA256Hash)
	}
	if callCount != 2 {
		t.Errorf("computeHash call count = %d, want 2 (one per item with FilePath)", callCount)
	}
}

// TestEnrichWithHash_NilCache verifies that a nil cache map does not panic —
// items with a FilePath fall through to computeHash.
func TestEnrichWithHash_NilCache(t *testing.T) {
	items := []software.SoftwareInfo{
		{Name: "App", Source: "programs", FilePath: "/opt/app"},
	}

	// Must not panic.
	result := software.EnrichWithHash(items, nil, mockHasher("ff00ff", nil))

	if result[0].SHA256Hash != "ff00ff" {
		t.Errorf("SHA256Hash = %q, want ff00ff", result[0].SHA256Hash)
	}
}

// TestEnrichWithHash_MixedItems exercises the full enrichment matrix in a
// single pass:
//
//   - item with no FilePath → skipped
//   - item with cache hit   → reuses cached hash, no call
//   - item with cache miss  → computeHash called, hash set
//   - item with hash error  → hash stays empty, pass continues
func TestEnrichWithHash_MixedItems(t *testing.T) {
	cache := map[string]string{
		"Cached App\x00programs": "cached-hash",
	}

	calls := 0
	hashFn := func(path string) (string, error) {
		calls++
		if path == "/broken" {
			return "", errors.New("no permission")
		}
		return "computed-hash", nil
	}

	items := []software.SoftwareInfo{
		{Name: "No Path App", Source: "deb_packages", FilePath: ""},   // skip
		{Name: "Cached App", Source: "programs", FilePath: "/cached"}, // cache hit
		{Name: "New App", Source: "programs", FilePath: "/new"},       // cache miss
		{Name: "Broken App", Source: "programs", FilePath: "/broken"}, // hash error
	}

	result := software.EnrichWithHash(items, cache, hashFn)

	if result[0].SHA256Hash != "" {
		t.Errorf("No Path App: want empty hash, got %q", result[0].SHA256Hash)
	}
	if result[1].SHA256Hash != "cached-hash" {
		t.Errorf("Cached App: want cached-hash, got %q", result[1].SHA256Hash)
	}
	if result[2].SHA256Hash != "computed-hash" {
		t.Errorf("New App: want computed-hash, got %q", result[2].SHA256Hash)
	}
	if result[3].SHA256Hash != "" {
		t.Errorf("Broken App: want empty hash on error, got %q", result[3].SHA256Hash)
	}
	// Only New App and Broken App should have triggered computeHash.
	if calls != 2 {
		t.Errorf("computeHash call count = %d, want 2", calls)
	}
}

// TestEnrichWithHash_EmptyList verifies no panic on an empty input.
func TestEnrichWithHash_EmptyList(t *testing.T) {
	result := software.EnrichWithHash(nil, nil, mockHasher("x", nil))
	if result != nil && len(result) != 0 {
		t.Errorf("expected nil/empty result for nil input, got %v", result)
	}
}

// TestEnrichWithHash_InPlaceModification verifies that the original slice is
// modified in place (same backing array).
func TestEnrichWithHash_InPlaceModification(t *testing.T) {
	items := []software.SoftwareInfo{
		{Name: "App", Source: "programs", FilePath: "/opt/app"},
	}
	originalPtr := &items[0]

	result := software.EnrichWithHash(items, nil, mockHasher("hash123", nil))

	if &result[0] != originalPtr {
		t.Error("EnrichWithHash should modify the slice in place, not return a copy")
	}
}
