package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/config"
)

// TestLoad_UTF8BOM is a regression test for a Windows service outage.
//
// PowerShell 5.1's Set-Content and Out-File -Encoding UTF8 prepend a UTF-8 BOM,
// so any operator who edits config.json with them silently makes it unparseable
// to encoding/json. That failure is disproportionately expensive to diagnose:
// Load fails, main exits via log.Fatalf before svc.Run reaches
// StartServiceCtrlDispatcher, and the SCM reports a generic 1053 with events
// 7000/7009 carrying a canned "30000 milliseconds" string. It presents as a
// startup timeout, which is the one thing it is not.
func TestLoad_UTF8BOM(t *testing.T) {
	body := `{
  "supabase_url": "https://example.supabase.co",
  "supabase_key": "test-key",
  "telemetry_enabled": true,
  "telemetry_collect_interval": "2m"
}`

	cases := []struct {
		name string
		data []byte
	}{
		{"with BOM", append([]byte{0xEF, 0xBB, 0xBF}, body...)},
		{"without BOM", []byte(body)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, tc.data, 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("Load() returned error: %v", err)
			}
			if cfg == nil {
				t.Fatal("Load() returned nil config")
			}
			if cfg.SupabaseURL != "https://example.supabase.co" {
				t.Errorf("SupabaseURL = %q, want %q", cfg.SupabaseURL, "https://example.supabase.co")
			}
			if !cfg.TelemetryEnabled {
				t.Error("TelemetryEnabled = false, want true")
			}
		})
	}
}

// TestLoad_BOMOnlyStrippedAtStart guards the narrow fix: a BOM is removed only
// as a prefix. The same bytes appearing inside the document are ordinary
// content and must not be silently rewritten.
func TestLoad_BOMOnlyStrippedAtStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := "{\"supabase_url\": \"https://example.supabase.co\", \"agent_secret\": \"\xEF\xBB\xBFsecret\"}"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.AgentSecret != "\xEF\xBB\xBFsecret" {
		t.Errorf("AgentSecret = %q, want the value to keep its interior bytes", cfg.AgentSecret)
	}
}

// TestLoad_MalformedJSONVariants verifies a malformed config is a hard,
// described error
// rather than a silent fallback to defaults.
//
// Falling back would be the more dangerous behaviour: an agent that starts with
// default settings after failing to read its real config would run with no
// Supabase URL, no credentials and every feature at its shipped default, while
// reporting a clean startup. Failing loudly is what lets the operator see that
// the file — not the agent — is broken.
func TestLoad_MalformedJSONVariants(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"truncated object", `{"supabase_url": "https://example.supabase.co"`},
		{"trailing comma", `{"supabase_url": "https://example.supabase.co",}`},
		{"not an object", `["supabase_url"]`},
		{"plain text", "this is not json at all"},
		{"BOM then garbage", "ï»¿not json either"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			cfg, err := config.Load(path)
			if err == nil {
				t.Fatalf("Load() succeeded on malformed config; got %+v", cfg)
			}
			if !strings.Contains(err.Error(), "parse config") {
				t.Errorf("error = %q, want it to name the parse failure", err)
			}
		})
	}
}

// TestLoad_MissingFile covers first-run provisioning: no config file yet is a
// normal state, not an error. Load must return the built-in defaults and mint
// the identifiers the agent needs before it can register.
func TestLoad_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist", "config.json")

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() on a missing file returned error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil config")
	}

	if cfg.DeviceID == "" {
		t.Error("DeviceID was not generated")
	}
	if cfg.AgentID == "" {
		t.Error("AgentID was not generated")
	}
	if !cfg.SoftwareSyncEnabled {
		t.Error("SoftwareSyncEnabled default was lost")
	}
	// Telemetry stays off until it is explicitly switched on.
	if cfg.TelemetryEnabled {
		t.Error("TelemetryEnabled defaulted to true")
	}
	// Privacy-sensitive collection stays opt-in.
	if cfg.ProcessesCollectCmdline {
		t.Error("ProcessesCollectCmdline defaulted to true")
	}
}

// TestLoad_PlainUTF8NoBOM is the control case for the BOM tests above: an
// ordinary UTF-8 file, including non-ASCII content, must parse unchanged.
func TestLoad_PlainUTF8NoBOM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := `{
  "supabase_url": "https://example.supabase.co",
  "supabase_key": "test-key",
  "agent_secret": "paßwort-éàü",
  "telemetry_collect_interval": "7m"
}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.AgentSecret != "paßwort-éàü" {
		t.Errorf("AgentSecret = %q, want the decoded non-ASCII value", cfg.AgentSecret)
	}
	if got := cfg.GetTelemetryCollectInterval(); got != 7*time.Minute {
		t.Errorf("TelemetryCollectInterval = %v, want 7m", got)
	}
}

// TestLoad_BOMDoesNotSurviveIntoValues pairs with
// TestLoad_BOMOnlyStrippedAtStart from the other direction: after a leading BOM
// is stripped, the parsed values must be exactly what the document said, with
// no residue at the front of the first field.
func TestLoad_BOMDoesNotSurviveIntoValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := append([]byte{0xEF, 0xBB, 0xBF},
		[]byte(`{"supabase_url":"https://example.supabase.co","agent_secret":"plain"}`)...)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.AgentSecret != "plain" {
		t.Errorf("AgentSecret = %q, want %q", cfg.AgentSecret, "plain")
	}
	if strings.HasPrefix(cfg.SupabaseURL, "ï") {
		t.Errorf("SupabaseURL = %q still carries BOM bytes", cfg.SupabaseURL)
	}
}
