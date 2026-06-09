package updater_test

import (
	"context"
	"testing"
	"time"

	"sentinelgo/internal/updater"
)

func TestAutoUpdateChecker_NilConfig(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// This runs in a goroutine and should stop when context is cancelled
	go updater.AutoUpdateChecker(ctx, nil)

	// Wait for context to cancel
	<-ctx.Done()
}

func TestCheckAndApply_InvalidConfig(t *testing.T) {
	requireNetwork(t)

	cfg := loadUpdaterTestConfig(t)
	// Set current version to match latest to skip actual download/update
	cfg.CurrentVersion = "v2.1.8"

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	token := getGitHubToken()
	err := updater.CheckAndApply(ctx, cfg, token)
	// Should not panic
	_ = err
}

func TestCheckAndApplyWithRetry_InvalidConfig(t *testing.T) {
	requireNetwork(t)

	cfg := loadUpdaterTestConfig(t)
	// Set current version to match latest to skip actual download/update
	cfg.CurrentVersion = "v2.1.8"

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	token := getGitHubToken()
	err := updater.CheckAndApplyWithRetry(ctx, cfg, token)
	// Should not panic
	_ = err
}

func TestAutoUpdateChecker_InvalidConfig(t *testing.T) {
	cfg := loadUpdaterTestConfig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// This runs in a goroutine and should stop when context is cancelled
	go updater.AutoUpdateChecker(ctx, cfg)

	// Wait for context to cancel
	<-ctx.Done()
}
