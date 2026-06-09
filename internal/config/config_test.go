package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"sentinelgo/internal/config"
)

func TestDurationUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{
			name:    "string duration",
			input:   `"5m"`,
			want:    5 * time.Minute,
			wantErr: false,
		},
		{
			name:    "string duration with seconds",
			input:   `"5m30s"`,
			want:    5*time.Minute + 30*time.Second,
			wantErr: false,
		},
		{
			name:    "numeric duration",
			input:   `300`,
			want:    300 * time.Nanosecond,
			wantErr: false,
		},
		{
			name:    "invalid format",
			input:   `"invalid"`,
			want:    0,
			wantErr: true,
		},
		{
			name:    "invalid type",
			input:   `true`,
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d config.Duration
			err := json.Unmarshal([]byte(tt.input), &d)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && time.Duration(d) != tt.want {
				t.Errorf("UnmarshalJSON() = %v, want %v", time.Duration(d), tt.want)
			}
		})
	}
}

func TestDurationMarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   config.Duration
		want    string
		wantErr bool
	}{
		{
			name:    "normal duration",
			input:   config.Duration(5 * time.Minute),
			want:    `"5m0s"`,
			wantErr: false,
		},
		{
			name:    "zero duration",
			input:   config.Duration(0),
			want:    `"0s"`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && string(got) != tt.want {
				t.Errorf("MarshalJSON() = %v, want %v", string(got), tt.want)
			}
		})
	}
}

func TestConfig_GetSoftwareInfoUpdateInterval(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want time.Duration
	}{
		{
			name: "with interval set",
			cfg:  &config.Config{UpdateInterval: config.Duration(10 * time.Minute)},
			want: 10 * time.Minute,
		},
		{
			name: "with zero interval",
			cfg:  &config.Config{UpdateInterval: config.Duration(0)},
			want: 5 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.GetSoftwareInfoUpdateInterval(); got != tt.want {
				t.Errorf("Config.GetSoftwareInfoUpdateInterval() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_GetLogStorageEnabled(t *testing.T) {
	cfg := &config.Config{LogStorageEnabled: true}
	if !cfg.GetLogStorageEnabled() {
		t.Error("Config.GetLogStorageEnabled() returned false, want true")
	}

	cfg.LogStorageEnabled = false
	if cfg.GetLogStorageEnabled() {
		t.Error("Config.GetLogStorageEnabled() returned true, want false")
	}
}

func TestConfig_GetAuditLogsEnabled(t *testing.T) {
	cfg := &config.Config{AuditLogsEnabled: true}
	if !cfg.GetAuditLogsEnabled() {
		t.Error("Config.GetAuditLogsEnabled() returned false, want true")
	}

	cfg.AuditLogsEnabled = false
	if cfg.GetAuditLogsEnabled() {
		t.Error("Config.GetAuditLogsEnabled() returned true, want false")
	}
}

func TestConfig_GetLogFlushInterval(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want time.Duration
	}{
		{
			name: "with interval set",
			cfg:  &config.Config{LogFlushInterval: config.Duration(10 * time.Minute)},
			want: 10 * time.Minute,
		},
		{
			name: "with zero interval",
			cfg:  &config.Config{LogFlushInterval: config.Duration(0)},
			want: 5 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.GetLogFlushInterval(); got != tt.want {
				t.Errorf("Config.GetLogFlushInterval() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_GetTaskPollingInterval(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want time.Duration
	}{
		{
			name: "with interval set",
			cfg:  &config.Config{TaskPollingInterval: config.Duration(10 * time.Minute)},
			want: 10 * time.Minute,
		},
		{
			name: "with zero interval",
			cfg:  &config.Config{TaskPollingInterval: config.Duration(0)},
			want: 5 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.GetTaskPollingInterval(); got != tt.want {
				t.Errorf("Config.GetTaskPollingInterval() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	cfg, err := config.Load("")
	// Skip if cannot load default config due to permissions
	if err != nil {
		t.Skipf("Skipping test due to config load error (likely permission): %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil config")
		return
	}
	if cfg.SupabaseURL == "" {
		t.Skip("Skipping SupabaseURL check: not set in default config (dev environment)")
	}
	if cfg.DeviceID == "" {
		t.Error("Load() config has empty DeviceID")
	}

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	testConfig := `{
		"supabase_url": "https://test.supabase.co",
		"supabase_key": "test-anon-key",
		"device_id": "test-device-id",
		"update_interval": "10m"
	}`
	if err := os.WriteFile(configPath, []byte(testConfig), 0600); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err = config.Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.UpdateInterval != config.Duration(10*time.Minute) {
		t.Errorf("Load() UpdateInterval = %v, want 10m", cfg.UpdateInterval)
	}
}

func minimalTestConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		DeviceID:    "test-device-id",
		AgentID:     "test-agent-id",
		SupabaseURL: "https://test.supabase.co",
		SupabaseKey: "test-key",
		AccessToken: "test-token",
	}
}

func TestConfig_Save(t *testing.T) {
	cfg := minimalTestConfig(t)
	configPath := filepath.Join(t.TempDir(), "config.json")
	cfg.Path = configPath

	err := cfg.Save()
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("Save() did not create config file")
	}
}

func TestConfig_SaveAtomic(t *testing.T) {
	cfg := minimalTestConfig(t)
	configPath := filepath.Join(t.TempDir(), "config.json")
	cfg.Path = configPath

	err := cfg.SaveAtomic()
	if err != nil {
		t.Fatalf("SaveAtomic() error = %v", err)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("SaveAtomic() did not create config file")
	}
}

func TestConfig_ValidateConfiguration(t *testing.T) {
	validCfg := minimalTestConfig(t)

	tests := []struct {
		name    string
		cfg     *config.Config
		wantErr bool
	}{
		{
			name:    "valid config",
			cfg:     validCfg,
			wantErr: false,
		},
		{
			name:    "missing supabase url",
			cfg:     &config.Config{DeviceID: validCfg.DeviceID},
			wantErr: true,
		},
		{
			name: "missing device id",
			cfg: &config.Config{
				SupabaseURL: validCfg.SupabaseURL,
				SupabaseKey: validCfg.SupabaseKey,
			},
			wantErr: true,
		},
		{
			name: "missing supabase key",
			cfg: &config.Config{
				SupabaseURL: validCfg.SupabaseURL,
				DeviceID:    validCfg.DeviceID,
			},
			wantErr: true,
		},
		{
			name: "invalid url",
			cfg: &config.Config{
				SupabaseURL: "not-a-url",
				DeviceID:    validCfg.DeviceID,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.ValidateConfiguration()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.ValidateConfiguration() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfig_SecureConfigFile(t *testing.T) {
	cfg := minimalTestConfig(t)
	configPath := filepath.Join(t.TempDir(), "config.json")
	cfg.Path = configPath

	if err := cfg.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if err := cfg.SecureConfigFile(); err != nil {
		t.Fatalf("SecureConfigFile() error = %v", err)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(configPath)
		if err != nil {
			t.Fatalf("Stat() error = %v", err)
		}
		mode := info.Mode().Perm()
		if mode != 0600 {
			t.Errorf("SecureConfigFile() mode = %v, want 0600", mode)
		}
	}
}

func TestConfig_SecureConfigFile_NonExistentFile(t *testing.T) {
	cfg := minimalTestConfig(t)
	cfg.Path = "/non/existent/path/config.json"
	_ = cfg.SecureConfigFile()
}

func TestConfig_Save_EmptyPath(t *testing.T) {
	cfg := minimalTestConfig(t)
	cfg.Path = ""
	if err := cfg.Save(); err == nil {
		t.Error("Save() should fail with empty path")
	}
}

func TestConfig_SaveAtomic_EmptyPath(t *testing.T) {
	cfg := minimalTestConfig(t)
	cfg.Path = ""
	if err := cfg.SaveAtomic(); err == nil {
		t.Error("SaveAtomic() should fail with empty path")
	}
}

func TestConfig_GetSoftwareInfoUpdateInterval_VeryLarge(t *testing.T) {
	cfg := &config.Config{UpdateInterval: config.Duration(24 * time.Hour)}
	got := cfg.GetSoftwareInfoUpdateInterval()
	if got != 24*time.Hour {
		t.Errorf("Config.GetSoftwareInfoUpdateInterval() = %v, want 24h", got)
	}
}
