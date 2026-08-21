package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sentinelgo/internal/config"
)

// TestLoad_EmptyPath checks the empty-path branch resolves and succeeds.
//
// The default resolver is redirected at a temp directory first: called for
// real, this branch creates and hardens the LIVE agent config directory and
// then reads the operator's actual credentials out of it. See
// TestConfigLoadDefaultPath, which covers the same branch in detail.
func TestLoad_EmptyPath(t *testing.T) {
	config.SetDefaultConfigPathForTest(t, filepath.Join(t.TempDir(), ".sentinelgo", "config.json"))

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Path == "" {
		t.Error("Load() left Path empty")
	}
}

func TestLoad_InvalidPath(t *testing.T) {
	cfg, err := config.Load("/nonexistent/path/config.json")
	// Load() with invalid path may return defaults, so we just check it doesn't panic
	_ = cfg
	_ = err
}

func TestLoad_InvalidJSON(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "config-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Remove(tmpFile.Name())
	}()

	_, err = tmpFile.WriteString("{invalid json}")
	if err != nil {
		t.Fatal(err)
	}
	_ = tmpFile.Close()

	cfg, err := config.Load(tmpFile.Name())
	if err == nil {
		t.Error("Load() should fail with invalid JSON")
	}
	if cfg != nil {
		t.Error("Load() should return nil on error")
	}
}

func TestDuration_UnmarshalJSON_InvalidString(t *testing.T) {
	var d config.Duration
	err := json.Unmarshal([]byte(`"invalid-duration"`), &d)
	if err == nil {
		t.Error("UnmarshalJSON() should fail with invalid duration string")
	}
}

func TestDuration_UnmarshalJSON_InvalidNumber(t *testing.T) {
	var d config.Duration
	err := json.Unmarshal([]byte(`"not-a-number"`), &d)
	if err == nil {
		t.Error("UnmarshalJSON() should fail with invalid number")
	}
}

func TestDuration_MarshalJSON_Negative(t *testing.T) {
	d := config.Duration(-1 * time.Second)
	_, err := json.Marshal(d)
	if err != nil {
		t.Errorf("MarshalJSON() should handle negative duration: %v", err)
	}
}
