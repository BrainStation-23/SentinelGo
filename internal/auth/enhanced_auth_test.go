package auth_test

import (
	"context"
	"testing"
	"time"

	"sentinelgo/internal/auth"
	"sentinelgo/internal/config"
)

func minimalTestConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		DeviceID:    "test-device-id",
		SupabaseURL: "https://test.supabase.co",
		SupabaseKey: "test-key",
	}
}

func TestNewEnhancedAuth(t *testing.T) {
	ea := auth.NewEnhancedAuth()
	if ea == nil {
		t.Fatal("NewEnhancedAuth() returned nil")
	}
}

func TestEnhancedAuth_ValidateAndRefreshTokens(t *testing.T) {
	cfg := minimalTestConfig(t)
	ea := auth.NewEnhancedAuth()

	tokenRefreshFunc := func(ctx context.Context, cfg *config.Config) error {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := ea.ValidateAndRefreshTokens(ctx, cfg, tokenRefreshFunc); err != nil {
		t.Errorf("ValidateAndRefreshTokens() error = %v", err)
	}
}

func TestEnhancedAuth_IsHealthy(t *testing.T) {
	ea := auth.NewEnhancedAuth()
	if !ea.IsHealthy() {
		t.Error("IsHealthy() should return true initially")
	}
}

func TestEnhancedAuth_GetStats(t *testing.T) {
	ea := auth.NewEnhancedAuth()
	_ = ea.GetStats()
}

func TestValidateConfig(t *testing.T) {
	validCfg := minimalTestConfig(t)

	if err := auth.ValidateConfig(validCfg); err != nil {
		t.Errorf("ValidateConfig() error = %v, want nil for valid config", err)
	}

	tests := []struct {
		name    string
		cfg     *config.Config
		wantErr bool
	}{
		{name: "nil config", cfg: nil, wantErr: true},
		{name: "missing supabase url", cfg: &config.Config{DeviceID: validCfg.DeviceID}, wantErr: true},
		{name: "missing device id", cfg: &config.Config{SupabaseURL: validCfg.SupabaseURL}, wantErr: true},
		{name: "invalid url", cfg: &config.Config{SupabaseURL: "not-a-url", DeviceID: validCfg.DeviceID}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.ValidateConfig(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
