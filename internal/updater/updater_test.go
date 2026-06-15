package updater_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/updater"
)

// requireNetwork gates updater tests that hit a live Supabase project. These
// are skipped unless SENTINELGO_UPDATER_NETWORK_TESTS=1 is set (and always
// skipped in -short mode). CheckAndApply against a real endpoint can download
// a binary and call os.Exit — only run when you explicitly intend that.
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
		SupabaseURL:    os.Getenv("SUPABASE_URL"),
		SupabaseKey:    os.Getenv("SUPABASE_KEY"),
		AutoUpdate:     false,
		CurrentVersion: "v0.0.0",
		Path:           filepath.Join(t.TempDir(), "config.json"),
	}
}

func TestCheckAndApply(t *testing.T) {
	requireNetwork(t)

	cfg := loadUpdaterTestConfig(t)
	cfg.AutoUpdate = false
	cfg.CurrentVersion = "v2.1.8"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := updater.CheckAndApply(ctx, cfg)
	// May fail due to network or missing release; should not panic.
	_ = err
}

func TestCheckAndApplyWithRetry(t *testing.T) {
	requireNetwork(t)

	cfg := loadUpdaterTestConfig(t)
	cfg.AutoUpdate = false
	cfg.CurrentVersion = "v2.1.8"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := updater.CheckAndApplyWithRetry(ctx, cfg)
	_ = err
}

func TestAutoUpdateChecker(t *testing.T) {
	cfg := loadUpdaterTestConfig(t)
	cfg.AutoUpdate = false

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	go updater.AutoUpdateChecker(ctx, cfg)
	<-ctx.Done()
}

func TestAutoUpdateChecker_CancelledContext(t *testing.T) {
	cfg := loadUpdaterTestConfig(t)
	cfg.AutoUpdate = false

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	go updater.AutoUpdateChecker(ctx, cfg)
	time.Sleep(10 * time.Millisecond)
}

func TestCheckAndApply_WithNilContext(t *testing.T) {
	requireNetwork(t)

	cfg := loadUpdaterTestConfig(t)
	cfg.AutoUpdate = false
	cfg.CurrentVersion = "v2.1.8"

	err := updater.CheckAndApply(context.TODO(), cfg)
	_ = err
}
