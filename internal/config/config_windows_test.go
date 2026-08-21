package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"sentinelgo/internal/config"
)

// TestConfigLoadWindowsPath tests that config fields load correctly from a file.
// The config is written to a per-test temp dir with known values so the test is
// hermetic — it does not depend on the exact flag values of the shared
// audit-config-sample.json (which other tests may also read).
func TestConfigLoadWindowsPath(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, ".sentinelgo", "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0750); err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}

	testConfig := `{
		"supabase_url": "https://test.supabase.co",
		"supabase_key": "test-anon-key",
		"device_id": "test-device-id",
		"log_storage_enabled": true,
		"software_sync_enabled": true,
		"audit_logs_enabled": true,
		"enable_task_polling": true
	}`
	if err := os.WriteFile(configPath, []byte(testConfig), 0600); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify critical fields are loaded from the config file
	if cfg.SupabaseURL == "" {
		t.Error("Expected SupabaseURL to be set")
	}

	if !cfg.LogStorageEnabled {
		t.Error("Expected LogStorageEnabled to be true")
	}

	if !cfg.SoftwareSyncEnabled {
		t.Error("Expected SoftwareSyncEnabled to be true")
	}

	if !cfg.AuditLogsEnabled {
		t.Error("Expected AuditLogsEnabled to be true")
	}

	if !cfg.EnableTaskPolling {
		t.Error("Expected EnableTaskPolling to be true")
	}
}

// TestConfigLoadMissingAgentID tests config loading when agent_id is missing
func TestConfigLoadMissingAgentID(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	// Load base config from sample file and remove agent_id
	testConfig := sampleConfigMap()
	delete(testConfig, "agent_id")

	data, err := json.MarshalIndent(testConfig, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal test config: %v", err)
	}
	err = os.WriteFile(configPath, data, 0644)
	if err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// AgentID should be from defaults (not empty since defaults are set)
	if cfg.AgentID == "" {
		t.Error("Expected AgentID to have default value, got empty string")
	}

	// SupabaseURL should still load correctly from sample
	if cfg.SupabaseURL == "" {
		t.Error("Expected SupabaseURL to be set")
	}
}

// TestConfigLoadMissingDeviceID tests config loading when device_id is missing
func TestConfigLoadMissingDeviceID(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	// Load base config from sample file and remove device_id
	testConfig := sampleConfigMap()
	delete(testConfig, "device_id")

	data, err := json.MarshalIndent(testConfig, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal test config: %v", err)
	}
	err = os.WriteFile(configPath, data, 0644)
	if err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// DeviceID should be auto-generated
	if cfg.DeviceID == "" {
		t.Error("Expected DeviceID to be auto-generated, got empty string")
	}
}

// TestConfigLoadMissingAccessToken tests config loading when access_token is missing
func TestConfigLoadMissingAccessToken(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	// Load base config from sample file and remove access_token
	testConfig := sampleConfigMap()
	delete(testConfig, "access_token")

	data, err := json.MarshalIndent(testConfig, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal test config: %v", err)
	}
	err = os.WriteFile(configPath, data, 0644)
	if err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// AccessToken is empty when not in config — no default is generated for auth tokens
	if cfg.AccessToken != "" {
		t.Error("Expected AccessToken to be empty when not present in config")
	}
}

// TestConfigLoadDefaultPath tests default path resolution.
//
// It used to call config.Load("") directly, which resolved the LIVE agent
// config path — C:\SentinelGo\.sentinelgo\config.json on Windows — and then
// created, hardened and read it. That made the test depend on the machine it
// ran on twice over: it failed outright where that directory is not writable by
// the test user, and where it is, it read the real agent's credentials and
// would have failed on any local edit that made the file unparseable. Redirect
// the resolver at a temp directory instead, so the branch is still exercised
// end to end without touching production state.
func TestConfigLoadDefaultPath(t *testing.T) {
	dir := t.TempDir()
	want := filepath.Join(dir, ".sentinelgo", "config.json")
	config.SetDefaultConfigPathForTest(t, want)

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Failed to load config with default path: %v", err)
	}

	if cfg.Path != want {
		t.Errorf("Config path = %q, want %q", cfg.Path, want)
	}
	if filepath.Base(filepath.Dir(cfg.Path)) != ".sentinelgo" {
		t.Errorf("Expected config path to include .sentinelgo directory, got '%s'", cfg.Path)
	}

	// The empty-path branch is the one that creates the directory holding the
	// agent's secrets, so assert it actually did.
	info, statErr := os.Stat(filepath.Dir(cfg.Path))
	if statErr != nil {
		t.Fatalf("config directory was not created: %v", statErr)
	}
	if !info.IsDir() {
		t.Errorf("%s is not a directory", filepath.Dir(cfg.Path))
	}

	// No file existed, so defaults must survive rather than being overwritten
	// by a partial parse.
	if cfg.DeviceID == "" {
		t.Error("DeviceID was not generated for a fresh config")
	}
}

// TestGetDefaultConfigPathShape checks the production resolver itself, with no
// side effects: it must name a config.json inside a .sentinelgo directory and
// must be absolute, so the path-traversal cleanup in Load has nothing to fix.
func TestGetDefaultConfigPathShape(t *testing.T) {
	got := config.RealDefaultConfigPath()

	if !filepath.IsAbs(got) {
		t.Errorf("default config path %q is not absolute", got)
	}
	if filepath.Base(got) != "config.json" {
		t.Errorf("default config path %q does not end in config.json", got)
	}
	if filepath.Base(filepath.Dir(got)) != ".sentinelgo" {
		t.Errorf("default config path %q is not inside a .sentinelgo directory", got)
	}
}

// TestConfigLoadDefaultPathDoesNotTouchProductionPath is the hygiene guarantee
// itself: with the resolver redirected, nothing under the real default path is
// read or created. Without this, a future edit could quietly reintroduce the
// dependency and the suite would keep passing on the one machine it was written
// on.
func TestConfigLoadDefaultPathDoesNotTouchProductionPath(t *testing.T) {
	production := config.RealDefaultConfigPath()
	before, beforeErr := os.Stat(production)

	dir := t.TempDir()
	config.SetDefaultConfigPathForTest(t, filepath.Join(dir, ".sentinelgo", "config.json"))
	if _, err := config.Load(""); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	after, afterErr := os.Stat(production)
	switch {
	case beforeErr != nil && afterErr == nil:
		t.Errorf("Load() created the production config at %s", production)
	case beforeErr == nil && afterErr == nil:
		if !before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() {
			t.Errorf("Load() modified the production config at %s", production)
		}
	}
}

// TestConfigSave tests saving configuration
func TestConfigSave(t *testing.T) {
	tempDir := t.TempDir()
	srcPath := filepath.Join(tempDir, "src-config.json")
	configPath := filepath.Join(tempDir, "config.json")

	data, err := json.MarshalIndent(sampleConfigMap(), "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal test config: %v", err)
	}
	if err := os.WriteFile(srcPath, data, 0600); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := config.Load(srcPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	cfg.Path = configPath

	// Save config
	err = cfg.Save()
	if err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("Config file was not created")
	}

	// Load and verify
	loadedCfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load saved config: %v", err)
	}

	if loadedCfg.SupabaseURL != cfg.SupabaseURL {
		t.Errorf("Expected SupabaseURL '%s', got '%s'", cfg.SupabaseURL, loadedCfg.SupabaseURL)
	}

	if loadedCfg.AuditLogsEnabled != cfg.AuditLogsEnabled {
		t.Errorf("Expected AuditLogsEnabled %v, got %v", cfg.AuditLogsEnabled, loadedCfg.AuditLogsEnabled)
	}

	if loadedCfg.EnableTaskPolling != cfg.EnableTaskPolling {
		t.Errorf("Expected EnableTaskPolling %v, got %v", cfg.EnableTaskPolling, loadedCfg.EnableTaskPolling)
	}
}

// TestConfigLoadInvalidJSON tests loading invalid JSON
func TestConfigLoadInvalidJSON(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	// Write invalid JSON
	invalidJSON := `{"agent_id": "test", invalid}`
	err := os.WriteFile(configPath, []byte(invalidJSON), 0644)
	if err != nil {
		t.Fatalf("Failed to write invalid JSON: %v", err)
	}

	// Should return error
	_, err = config.Load(configPath)
	if err == nil {
		t.Error("Expected error when loading invalid JSON, got nil")
	}
}

// TestConfigLoadNonExistentFile tests loading non-existent file
func TestConfigLoadNonExistentFile(t *testing.T) {
	nonExistentPath := filepath.Join(t.TempDir(), "nonexistent.json")

	// Should not return error, should use defaults
	cfg, err := config.Load(nonExistentPath)
	if err != nil {
		t.Fatalf("Failed to load non-existent config: %v", err)
	}

	// Should have default values
	if cfg.AgentID == "" {
		t.Error("Expected default AgentID, got empty string")
	}

	// Path should be set to the requested path
	if cfg.Path != nonExistentPath {
		t.Errorf("Expected path '%s', got '%s'", nonExistentPath, cfg.Path)
	}
}

// sampleConfigMap returns a minimal valid config map for test manipulation
// (e.g., deleting keys to test missing-field behavior). No file I/O.
func sampleConfigMap() map[string]interface{} {
	return map[string]interface{}{
		"supabase_url":          "https://example.supabase.co",
		"supabase_key":          "test-key",
		"device_id":             "test-device-id",
		"agent_id":              "test-agent-id",
		"access_token":          "test-access-token",
		"refresh_token":         "test-refresh-token",
		"audit_logs_enabled":    true,
		"enable_task_polling":   true,
		"log_storage_enabled":   true,
		"software_sync_enabled": true,
		"update_interval":       "5m",
		"log_flush_interval":    "5m",
		"task_polling_interval": "5m",
	}
}
