package taskstore_test

import (
	"os"
	"path/filepath"
	"testing"

	"sentinelgo/internal/config"
	"sentinelgo/internal/store"
	"sentinelgo/internal/taskstore"
)

func minimalTestConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		DeviceID:    "test-device-id",
		SupabaseURL: "https://test.supabase.co",
		SupabaseKey: "test-key",
		AccessToken: "test-token",
	}
}

func TestNewStore(t *testing.T) {
	// Create a temporary database file
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := store.NewTaskStore(dbPath)
	if err != nil {
		t.Errorf("NewStore() failed: %v", err)
	}
	if store == nil {
		t.Fatal("NewStore() returned nil")
	}
	t.Cleanup(func() { _ = store.Close() })
}

func TestNewStore_InvalidPath(t *testing.T) {
	// Try to create a store with an invalid path
	store, err := store.NewTaskStore("/invalid/path/that/does/not/exist/test.db")
	if err == nil {
		t.Error("NewStore() should fail with invalid path")
	}
	if store != nil {
		t.Error("NewStore() should return nil on error")
	}
}

func TestNewClient(t *testing.T) {
	cfg := minimalTestConfig(t)
	client := taskstore.NewClient(cfg.SupabaseURL, cfg.SupabaseKey, cfg.AccessToken)
	if client == nil {
		t.Fatal("NewClient() returned nil")
	}
}

func TestNewClient_EmptyURL(t *testing.T) {
	cfg := minimalTestConfig(t)
	client := taskstore.NewClient("", cfg.SupabaseKey, cfg.AccessToken)
	if client == nil {
		t.Fatal("NewClient() should handle empty URL")
	}
}

func TestNewClient_EmptyAccessToken(t *testing.T) {
	cfg := minimalTestConfig(t)
	client := taskstore.NewClient(cfg.SupabaseURL, cfg.SupabaseKey, "")
	if client == nil {
		t.Fatal("NewClient() should handle empty access token")
	}
}

func TestNewStore_WithExistingFile(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Create store first time
	store1, err := store.NewTaskStore(dbPath)
	if err != nil {
		t.Errorf("NewStore() failed: %v", err)
	}
	if store1 == nil {
		t.Fatal("NewStore() returned nil")
	}

	// Close first store
	_ = store1.Close()

	// Create store again with same file
	store2, err := store.NewTaskStore(dbPath)
	if err != nil {
		t.Errorf("NewStore() with existing file failed: %v", err)
	}
	if store2 == nil {
		t.Fatal("NewStore() returned nil")
	}

	// Clean up
	_ = store2.Close()
	_ = os.Remove(dbPath)
}
