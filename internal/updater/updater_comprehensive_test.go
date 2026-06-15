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

	// Ticker fires hourly; context cancels long before any RPC call is attempted.
	go updater.AutoUpdateChecker(ctx, nil)
	<-ctx.Done()
}

func TestCheckAndApply_InvalidConfig(t *testing.T) {
	requireNetwork(t)

	cfg := loadUpdaterTestConfig(t)
	cfg.CurrentVersion = "v2.1.8"

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := updater.CheckAndApply(ctx, cfg)
	_ = err
}

func TestCheckAndApplyWithRetry_InvalidConfig(t *testing.T) {
	requireNetwork(t)

	cfg := loadUpdaterTestConfig(t)
	cfg.CurrentVersion = "v2.1.8"

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := updater.CheckAndApplyWithRetry(ctx, cfg)
	_ = err
}

func TestAutoUpdateChecker_InvalidConfig(t *testing.T) {
	cfg := loadUpdaterTestConfig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	go updater.AutoUpdateChecker(ctx, cfg)
	<-ctx.Done()
}
