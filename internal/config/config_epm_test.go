package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/config"
)

func TestGetEPMWindowsTokenType(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  string
		want string
	}{
		{"unset defaults to elevated", "", config.EPMTokenElevated},
		{"explicit elevated", config.EPMTokenElevated, config.EPMTokenElevated},
		{"explicit system", config.EPMTokenSystem, config.EPMTokenSystem},
		{"explicit filtered", config.EPMTokenFiltered, config.EPMTokenFiltered},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{EPMWindowsTokenType: tc.set}
			if got := cfg.GetEPMWindowsTokenType(); got != tc.want {
				t.Errorf("GetEPMWindowsTokenType() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidateConfiguration_EPMTokenType(t *testing.T) {
	for _, tc := range []struct {
		name      string
		tokenType string
		wantErr   bool
	}{
		{"unset is valid", "", false},
		{"elevated", config.EPMTokenElevated, false},
		{"system", config.EPMTokenSystem, false},
		{"filtered", config.EPMTokenFiltered, false},
		{"unknown value", "superuser", true},
		{"wrong case", "Elevated", true},
		{"whitespace", " elevated", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := minimalTestConfig(t)
			cfg.EPMWindowsTokenType = tc.tokenType

			err := cfg.ValidateConfiguration()
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateConfiguration() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "epm_windows_token_type") {
				t.Errorf("error should name the offending key, got %v", err)
			}
		})
	}
}

// TestValidateConfiguration_EPMValidatedWhenDisabled pins that EPM settings are
// checked even with enable_epm=false, so a typo surfaces at startup instead of
// the first time an operator turns EPM on.
func TestValidateConfiguration_EPMValidatedWhenDisabled(t *testing.T) {
	cfg := minimalTestConfig(t)
	cfg.EPMEnabled = false
	cfg.EPMWindowsTokenType = "nonsense"

	if err := cfg.ValidateConfiguration(); err == nil {
		t.Error("expected validation to reject a bad EPM setting even while EPM is disabled")
	}
}

func TestValidateConfiguration_EPMPolicySyncInterval(t *testing.T) {
	cfg := minimalTestConfig(t)
	cfg.EPMPolicySyncInterval = config.Duration(-time.Minute)

	err := cfg.ValidateConfiguration()
	if err == nil {
		t.Fatal("expected a negative epm_policy_sync_interval to be rejected")
	}
	if !strings.Contains(err.Error(), "epm_policy_sync_interval") {
		t.Errorf("error should name the offending key, got %v", err)
	}
}

// TestLoad_DoesNotPrefillEPMTokenType is the guard for the config-stickiness
// rule. Load unmarshals over a struct pre-filled with defaults and SaveAtomic
// marshals the whole struct with no omitempty, so anything Load pre-fills gets
// written to every agent's config.json on the next token refresh and becomes
// permanent — a later change to the code default would never reach that host.
// New EPM settings must therefore stay at their zero value in Load and resolve
// their default through a Get accessor.
func TestLoad_DoesNotPrefillEPMTokenType(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	seed := map[string]any{
		"supabase_url": "https://test.supabase.co",
		"supabase_key": "test-key",
		"device_id":    "test-device-id",
	}
	data, err := json.Marshal(seed)
	if err != nil {
		t.Fatalf("marshal seed config: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write seed config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.EPMWindowsTokenType != "" {
		t.Errorf("Load pre-filled EPMWindowsTokenType with %q; it must stay empty so the "+
			"code default stays changeable after the first SaveAtomic", cfg.EPMWindowsTokenType)
	}
	if got := cfg.GetEPMWindowsTokenType(); got != config.EPMTokenElevated {
		t.Errorf("accessor must still resolve the default: got %q, want %q", got, config.EPMTokenElevated)
	}
}

// TestEPMTokenType_SurvivesSaveLoadRoundTrip confirms an operator-set value is
// persisted and read back unchanged — the escape hatch has to actually stick.
func TestEPMTokenType_SurvivesSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	cfg := minimalTestConfig(t)
	cfg.Path = path
	cfg.EPMWindowsTokenType = config.EPMTokenFiltered
	if err := cfg.SaveAtomic(); err != nil {
		t.Fatalf("SaveAtomic: %v", err)
	}

	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := reloaded.GetEPMWindowsTokenType(); got != config.EPMTokenFiltered {
		t.Errorf("round-tripped token type = %q, want %q", got, config.EPMTokenFiltered)
	}
}
