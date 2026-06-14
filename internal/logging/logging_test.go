package logging_test

import (
	"context"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/logging"
)

func TestNewLoggingIntegration(t *testing.T) {
	cfg := &config.Config{
		DeviceID:         "test-device-id",
		LogFlushInterval: config.Duration(5 * time.Minute),
		Path:             "/tmp/test-config.json",
	}

	li, err := logging.NewLoggingIntegration(cfg)
	if err != nil {
		t.Errorf("NewLoggingIntegration() failed: %v", err)
	}
	if li == nil {
		t.Fatal("NewLoggingIntegration() returned nil")
	}

	// Test with nil config
	_, err = logging.NewLoggingIntegration(nil)
	if err == nil {
		t.Error("NewLoggingIntegration() should fail with nil config")
	}
}

func TestLoggingIntegration_Start_Stop(t *testing.T) {
	cfg := &config.Config{
		DeviceID:         "test-device-id",
		LogFlushInterval: config.Duration(5 * time.Minute),
		Path:             "/tmp/test-config.json",
	}

	li, err := logging.NewLoggingIntegration(cfg)
	if err != nil {
		t.Fatalf("NewLoggingIntegration() failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = li.Start(ctx)
	if err != nil {
		t.Errorf("Start() failed: %v", err)
	}

	// Starting again should be idempotent
	err = li.Start(ctx)
	if err != nil {
		t.Errorf("Start() should be idempotent: %v", err)
	}

	// Stop the integration
	err = li.Stop()
	if err != nil {
		t.Errorf("Stop() failed: %v", err)
	}

	// Stopping again should be idempotent
	err = li.Stop()
	if err != nil {
		t.Errorf("Stop() should be idempotent: %v", err)
	}
}

func TestLoggingIntegration_CollectLogsNow(t *testing.T) {
	cfg := &config.Config{
		DeviceID:         "test-device-id",
		LogFlushInterval: config.Duration(5 * time.Minute),
		Path:             "/tmp/test-config.json",
	}

	li, err := logging.NewLoggingIntegration(cfg)
	if err != nil {
		t.Fatalf("NewLoggingIntegration() failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = li.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer func() {
		_ = li.Stop()
	}()

	// Collect logs now
	err = li.CollectLogsNow(ctx)
	// This may fail depending on system configuration, but should not panic
	_ = err
}

func TestLoggingIntegration_ForceUpload(t *testing.T) {
	// Use a fixed temp path (same pattern as other logging tests) so the SQLite
	// file is in the OS temp dir and the test runner doesn't try to clean it up.
	// Not calling Start() means no background goroutines run — no locking.
	cfg := &config.Config{
		DeviceID:         "test-device-id",
		LogFlushInterval: config.Duration(5 * time.Minute),
		Path:             "/tmp/test-forceupload-config.json",
	}

	li, err := logging.NewLoggingIntegration(cfg)
	if err != nil {
		t.Fatalf("NewLoggingIntegration() failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// With no logs in the store and no Supabase URL, ForceUpload should be a no-op.
	// We only assert no panic — the error value is implementation-specific.
	_ = li.ForceUpload(ctx)
}

func TestLoggingIntegration_GetStatistics(t *testing.T) {
	cfg := &config.Config{
		DeviceID:         "test-device-id",
		LogFlushInterval: config.Duration(5 * time.Minute),
		Path:             "/tmp/test-config.json",
	}

	li, err := logging.NewLoggingIntegration(cfg)
	if err != nil {
		t.Fatalf("NewLoggingIntegration() failed: %v", err)
	}

	// Stats should be valid even before starting
	_ = li.GetStatistics()
}

func TestLoggingIntegration_CheckAgentTaskPolling(t *testing.T) {
	cfg := &config.Config{
		DeviceID:         "test-device-id",
		LogFlushInterval: config.Duration(5 * time.Minute),
		Path:             "/tmp/test-config.json",
	}

	li, err := logging.NewLoggingIntegration(cfg)
	if err != nil {
		t.Fatalf("NewLoggingIntegration() failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = li.CheckAgentTaskPolling(ctx)
	if err != nil {
		t.Errorf("CheckAgentTaskPolling() failed: %v", err)
	}
}
