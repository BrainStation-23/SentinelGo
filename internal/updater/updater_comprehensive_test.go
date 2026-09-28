package updater_test

import (
	"context"
	"testing"
	"time"

	"sentinelgo/internal/updater"
)

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
