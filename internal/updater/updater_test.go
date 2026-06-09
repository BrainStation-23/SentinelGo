package updater_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/updater"
)

// requireNetwork gates updater tests that hit the real GitHub API. These are
// skipped unless SENTINELGO_UPDATER_NETWORK_TESTS=1 is set (and always skipped
// in -short mode). The gate is opt-in because CheckAndApply performs a REAL
// update against the live release: if the latest published release is newer
// than the test's CurrentVersion it will download the new binary, replace files
// on disk, and call os.Exit via restart() — destructive and not hermetic. Only
// run these when you explicitly intend to exercise the live update path.
func requireNetwork(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping network-dependent updater test in short mode")
	}
	if os.Getenv("SENTINELGO_UPDATER_NETWORK_TESTS") != "1" {
		t.Skip("skipping network-dependent updater test; set SENTINELGO_UPDATER_NETWORK_TESTS=1 to run")
	}
}

// loadUpdaterTestConfig returns a minimal config with Path pointing at a per-test
// temp dir, so any config.Save/SaveAtomic triggered by the updater writes there
// instead of the machine's real config path (or an empty path, which fails the
// atomic rename). This keeps the updater tests isolated from each other and the
// host machine.
func loadUpdaterTestConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		DeviceID:       "test-device-id",
		SupabaseURL:    "https://test.supabase.co",
		SupabaseKey:    "test-key",
		AutoUpdate:     false,
		CurrentVersion: "v0.0.0",
		Path:           filepath.Join(t.TempDir(), "config.json"),
	}
}

func getGitHubToken() string {
	// Load token from .env file for tests only
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		// Try to load from .env file if not in environment
		if data, err := os.ReadFile("../../.env"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "GITHUB_TOKEN=") {
					token = strings.TrimPrefix(line, "GITHUB_TOKEN=")
					break
				}
			}
		}
	}
	return token
}

func TestCheckAndApply(t *testing.T) {
	requireNetwork(t)

	cfg := loadUpdaterTestConfig(t)
	// Disable auto-update for testing
	cfg.AutoUpdate = false
	// Set current version to match latest to skip actual download/update
	cfg.CurrentVersion = "v2.1.8"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	token := getGitHubToken()
	err := updater.CheckAndApply(ctx, cfg, token)
	// This may fail due to network or other reasons, but should not panic
	_ = err
}

func TestCheckAndApplyWithRetry(t *testing.T) {
	requireNetwork(t)

	cfg := loadUpdaterTestConfig(t)
	// Disable auto-update for testing
	cfg.AutoUpdate = false
	// Set current version to match latest to skip actual download/update
	cfg.CurrentVersion = "v2.1.8"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	token := getGitHubToken()
	err := updater.CheckAndApplyWithRetry(ctx, cfg, token)
	// This may fail due to network or other reasons, but should not panic
	_ = err
}

func TestAutoUpdateChecker(t *testing.T) {
	cfg := loadUpdaterTestConfig(t)
	// Disable auto-update for testing
	cfg.AutoUpdate = false

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// This runs in a goroutine and should stop when context is cancelled.
	// The ticker fires hourly, so the context cancels long before any network
	// call is attempted.
	go updater.AutoUpdateChecker(ctx, cfg)

	// Wait for context to cancel
	<-ctx.Done()
}

func TestAutoUpdateChecker_CancelledContext(t *testing.T) {
	cfg := loadUpdaterTestConfig(t)
	cfg.AutoUpdate = false

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	go updater.AutoUpdateChecker(ctx, cfg)

	// Wait a bit to ensure it handles cancellation
	time.Sleep(10 * time.Millisecond)
}

func TestCheckAndApply_WithNilContext(t *testing.T) {
	requireNetwork(t)

	cfg := loadUpdaterTestConfig(t)
	cfg.AutoUpdate = false
	// Set current version to match latest to skip actual download/update
	cfg.CurrentVersion = "v2.1.8"

	token := getGitHubToken()
	err := updater.CheckAndApply(context.TODO(), cfg, token)
	_ = err
}
