package logging_test

import (
	"testing"

	"sentinelgo/internal/config"
	"sentinelgo/internal/logging"
)

func TestNewLoggingIntegration_NilConfig(t *testing.T) {
	li, err := logging.NewLoggingIntegration(nil)
	if err == nil {
		t.Error("NewLoggingIntegration() should fail with nil config")
	}
	if li != nil {
		t.Error("NewLoggingIntegration() should return nil on error")
	}
}

func TestNewLoggingIntegration_EmptyConfig(t *testing.T) {
	cfg := &config.Config{DeviceID: "test-device-id"}
	li, err := logging.NewLoggingIntegration(cfg)
	// Just verify it doesn't panic; success/failure depends on runtime state
	_ = li
	_ = err
}

func TestNewUploader_NilConfig(t *testing.T) {
	uploader := logging.NewUploader(nil, nil)
	if uploader == nil {
		t.Fatal("NewUploader() should handle nil config")
	}
}

func TestNewUploader_NilStats(t *testing.T) {
	cfg := &config.Config{DeviceID: "test-device-id"}
	uploader := logging.NewUploader(cfg, nil)
	if uploader == nil {
		t.Fatal("NewUploader() should handle nil stats")
	}
}

func TestNewCheckpointStore_EmptyDir(t *testing.T) {
	cp := logging.NewCheckpointStore("")
	if cp == nil {
		t.Fatal("NewCheckpointStore() should handle empty directory")
	}
}

func TestNewCheckpointStore_Load_NonExistentFile(t *testing.T) {
	tmpDir := t.TempDir()
	cp := logging.NewCheckpointStore(tmpDir)

	err := cp.Load()
	if err != nil {
		t.Errorf("Load() should handle non-existent file: %v", err)
	}
}

func TestCheckpointStore_Update_EmptyData(t *testing.T) {
	tmpDir := t.TempDir()
	cp := logging.NewCheckpointStore(tmpDir)

	data := logging.CheckpointData{}

	cp.Update(data)
	// Should not panic
}

func TestCheckpointStore_Update_NilData(t *testing.T) {
	tmpDir := t.TempDir()
	cp := logging.NewCheckpointStore(tmpDir)

	cp.Update(nil)
	// Should not panic
}

func TestLoggingStats_AllZero(t *testing.T) {
	stats := logging.LoggingStats{}

	if stats.LogsCollected != 0 {
		t.Errorf("LogsCollected should be 0, got %d", stats.LogsCollected)
	}
	if stats.LogsStored != 0 {
		t.Errorf("LogsStored should be 0, got %d", stats.LogsStored)
	}
	if stats.LogsUploaded != 0 {
		t.Errorf("LogsUploaded should be 0, got %d", stats.LogsUploaded)
	}
	if stats.UploadErrors != 0 {
		t.Errorf("UploadErrors should be 0, got %d", stats.UploadErrors)
	}
}
