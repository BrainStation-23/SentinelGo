package software

import (
	"context"
	"path/filepath"
	"testing"

	"sentinelgo/internal/config"
)

// mkChromeExt creates a Chrome extension fixture under home's Default profile:
// .../Default/Extensions/<extID>/<version>_0/manifest.json.
func mkChromeExt(t *testing.T, home, extID, name, version string) {
	t.Helper()
	base := chromeExtDirGlobs(home)[0] // the literal Default/Extensions path
	writeManifest(t, filepath.Join(base, extID, version+"_0"), name, version)
}

// TestGetChromeExtensions_MultipleUsers verifies extensions are collected from
// every home returned by userHomeDirs(), not just the service account's.
func TestGetChromeExtensions_MultipleUsers(t *testing.T) {
	home1 := t.TempDir()
	home2 := t.TempDir()
	mkChromeExt(t, home1, "ext-one-id", "Ext One", "1.0")
	mkChromeExt(t, home2, "ext-two-id", "Ext Two", "2.0")

	orig := userHomeDirs
	userHomeDirs = func() []string { return []string{home1, home2} }
	t.Cleanup(func() { userHomeDirs = orig })

	s := &SoftwareService{}
	exts, _ := s.getChromeExtensions()

	names := make(map[string]bool)
	for _, e := range exts {
		names[e.Name] = true
	}
	if !names["Ext One"] || !names["Ext Two"] {
		t.Errorf("expected extensions from both users, got %v", exts)
	}
}

// fakeCatalog records Upsert/DeleteNotIn calls for assertions.
type fakeCatalog struct {
	upserts  int
	prunes   int
	lastKeys []string
}

func (f *fakeCatalog) Upsert(_ string, _ []SoftwareInfo) error { f.upserts++; return nil }
func (f *fakeCatalog) DeleteNotIn(_ string, keys []string) error {
	f.prunes++
	f.lastKeys = keys
	return nil
}

// TestSyncCatalog_PrunesOnlyWhenComplete is the partial-scan guard: a complete
// scan prunes stale entries, a partial scan must not (or live software is lost).
// The send fails (no Supabase URL), but persistence runs first, so the catalog
// interaction is still exercised.
func TestSyncCatalog_PrunesOnlyWhenComplete(t *testing.T) {
	svc := NewSoftwareService()
	list := []SoftwareInfo{{Name: "a", Source: "programs"}}

	partial := &fakeCatalog{}
	_, _ = svc.SyncCatalog(context.Background(), partial, "agent-1", list, false, &config.Config{})
	if partial.upserts != 1 {
		t.Errorf("partial scan: upserts = %d, want 1", partial.upserts)
	}
	if partial.prunes != 0 {
		t.Errorf("partial scan must NOT prune, but prunes = %d", partial.prunes)
	}

	complete := &fakeCatalog{}
	_, _ = svc.SyncCatalog(context.Background(), complete, "agent-1", list, true, &config.Config{})
	if complete.prunes != 1 {
		t.Errorf("complete scan must prune, but prunes = %d", complete.prunes)
	}
	if len(complete.lastKeys) != 1 || complete.lastKeys[0] != "a\x00programs" {
		t.Errorf("prune keys = %v, want [a\\x00programs]", complete.lastKeys)
	}
}

// TestSyncCatalog_NilCatalogStillSends ensures a nil catalog is tolerated (the
// no-store fallback path) without panicking.
func TestSyncCatalog_NilCatalogStillSends(t *testing.T) {
	svc := NewSoftwareService()
	// Send will fail (no URL configured), but must not panic on the nil catalog.
	_, err := svc.SyncCatalog(context.Background(), nil, "agent-1",
		[]SoftwareInfo{{Name: "a", Source: "programs"}}, true, &config.Config{})
	if err == nil {
		t.Skip("send unexpectedly succeeded; nil-catalog path still did not panic")
	}
}
