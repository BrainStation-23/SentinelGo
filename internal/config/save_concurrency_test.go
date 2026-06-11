package config

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// newSaveableConfig builds a minimal config that passes validateConfig so
// SaveAtomic can run, writing to a temp path.
func newSaveableConfig(t *testing.T) *Config {
	t.Helper()
	return &Config{
		Path:             filepath.Join(t.TempDir(), "config.json"),
		SupabaseURL:      "https://example.supabase.co",
		SupabaseKey:      "anon-key",
		DeviceID:         "dev-1",
		UpdateInterval:   Duration(5 * time.Minute),
		LogFlushInterval: Duration(5 * time.Minute),
		AccessToken:      "initial",
		RefreshToken:     "initial",
	}
}

// TestSaveAtomic_ConcurrentSavesAndTokenWrites exercises concurrent SaveAtomic
// and SetTokens calls. Under -race this fails if the token writes or the temp
// file handling are not properly synchronised (the old fixed ".tmp" path and
// unguarded field writes raced).
func TestSaveAtomic_ConcurrentSavesAndTokenWrites(t *testing.T) {
	cfg := newSaveableConfig(t)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			cfg.SetTokens("access", "refresh")
		}(i)
		go func() {
			defer wg.Done()
			if err := cfg.SaveAtomic(); err != nil {
				t.Errorf("SaveAtomic: %v", err)
			}
		}()
	}
	wg.Wait()

	// File must be loadable and intact (not torn) after the concurrent churn.
	loaded, err := Load(cfg.Path)
	if err != nil {
		t.Fatalf("Load after concurrent saves: %v", err)
	}
	if loaded.SupabaseURL != "https://example.supabase.co" {
		t.Errorf("config corrupted: SupabaseURL = %q", loaded.SupabaseURL)
	}
}
