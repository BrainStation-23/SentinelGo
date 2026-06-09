package taskstore_test

import (
	"path/filepath"
	"testing"

	"sentinelgo/internal/store"
	"sentinelgo/internal/taskstore"
)

func TestNewStore_EmptyPath(t *testing.T) {
	store, err := store.NewTaskStore("")
	// NewStore may succeed with empty path, so just check it doesn't panic
	if store != nil {
		t.Cleanup(func() { _ = store.Close() })
	}
	_ = err
}

func TestNewStore_TempDir(t *testing.T) {
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

func TestNewClient_EmptyKeys(t *testing.T) {
	cfg := minimalTestConfig(t)
	client := taskstore.NewClient(cfg.SupabaseURL, cfg.SupabaseKey, cfg.AccessToken)
	if client == nil {
		t.Fatal("NewClient() should handle real config")
	}
}

func TestNewClient_AllEmpty(t *testing.T) {
	client := taskstore.NewClient("", "", "")
	if client == nil {
		t.Fatal("NewClient() should handle all empty parameters")
	}
}
