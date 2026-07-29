package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// Duration is a wrapper around time.Duration for JSON marshaling
type Duration time.Duration

// UnmarshalJSON implements json.Unmarshaler for Duration, supporting both string ("5m") and numeric formats.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		*d = Duration(time.Duration(value))
		return nil
	case string:
		tmp, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		*d = Duration(tmp)
		return nil
	default:
		return fmt.Errorf("invalid duration")
	}
}

// MarshalJSON implements json.Marshaler for Duration, encoding as a duration string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// Platform-specific config paths
const (
	// Windows: ProgramData folder for system-wide configuration
	WindowsConfigPath = `C:\SentinelGo\.sentinelgo\config.json`
	// Linux: /etc/opt for system-wide configuration
	LinuxConfigPath = `/opt/sentinelgo/.sentinelgo/config.json`
	// macOS: /Library/Application Support for system-wide configuration
	MacConfigPath = `/opt/sentinelgo/.sentinelgo/config.json`
)

// GetDefaultConfigPath returns the platform-specific default config path
func GetDefaultConfigPath() string {
	switch runtime.GOOS {
	case "windows":
		return WindowsConfigPath
	case "linux":
		return LinuxConfigPath
	case "darwin":
		return MacConfigPath
	default:
		// Fallback to home directory for unsupported platforms
		home, err := os.UserHomeDir()
		if err != nil {
			return "/opt/sentinelgo/.sentinelgo/config.json"
		}
		return filepath.Join(home, ".sentinelgo", "config.json")
	}
}

// Version is injected at build time via -ldflags "-X sentinelgo/internal/config.Version=...".
// It MUST have no initializer here: the linker's -X can only set a string variable
// that is uninitialized (or set to a constant). The env/default fallback is applied
// in init() below, so a value is always present even for plain `go build`.
var Version string

func init() {
	if Version == "" {
		Version = "dev"
	}
}

type Config struct {
	Path                    string   `json:"-"`               // Path to the config file
	UpdateInterval          Duration `json:"update_interval"` // Software sync interval (supports both "5m0s" and numeric formats)
	CurrentVersion          string   `json:"current_version"`
	DeviceID                string   `json:"device_id"`                  // persistent unique identifier
	AutoUpdate              bool     `json:"auto_update"`                // Enable automatic updates
	AutoUpdateInterval      Duration `json:"auto_update_interval"`       // How often to check for a new release (default 24h)
	AgentInfoUpdateInterval Duration `json:"agent_info_update_interval"` // How often to push inventory to Supabase (default 1h)
	TaskPollingInterval     Duration `json:"task_polling_interval"`      // Task polling interval (supports both "5m0s" and numeric formats)
	EnableTaskPolling       bool     `json:"enable_task_polling"`        // Enable task polling service
	TaskExecutionInterval   Duration `json:"task_execution_interval"`    // Task execution interval (supports both "5m0s" and numeric formats)
	TaskDBPath              string   `json:"task_db_path"`               // Override task database path (for testing)
	// Supabase configuration
	SupabaseURL  string `json:"supabase_url"`  // Supabase project URL
	SupabaseKey  string `json:"supabase_key"`  // Supabase anon/public API key (for apikey header)
	AgentSecret  string `json:"agent_secret"`  // Agent secret for authentication
	AgentID      string `json:"agent_id"`      // Custom agent UUID field (maps to agent_uuid database column)
	AccessToken  string `json:"access_token"`  // JWT access token from Supabase
	RefreshToken string `json:"refresh_token"` // JWT refresh token from Supabase
	// Log collection configuration
	LogStorageEnabled bool     `json:"log_storage_enabled"` // Enable/disable log storage
	LogFlushInterval  Duration `json:"log_flush_interval"`  // Log collection/upload interval (supports both "5m0s" and numeric formats)
	// Service configuration
	SoftwareSyncEnabled    bool     `json:"software_sync_enabled"`    // Enable software synchronization
	AuditLogsEnabled       bool     `json:"audit_logs_enabled"`       // Enable audit logs service
	EdgeFunctionURL        string   `json:"edge_function_url"`        // Edge Function URL for software data
	ServicesSyncEnabled    bool     `json:"services_sync_enabled"`    // Enable OS services collection
	ServicesUpdateInterval Duration `json:"services_update_interval"` // How often to collect OS services (default 5m)
	// Endpoint Privilege Management (EPM) configuration
	EPMEnabled            bool     `json:"enable_epm"`               // Enable Endpoint Privilege Management (default false)
	EPMPolicySyncInterval Duration `json:"epm_policy_sync_interval"` // How often to sync EPM policy rules (default 5m)
	// EPMWindowsTokenType selects how the Windows enforcement transport derives
	// the token for an allowed elevation. "" means the code default; see
	// GetEPMWindowsTokenType for the values and their meaning.
	//
	// Deliberately NOT pre-filled in Load: SaveAtomic marshals the whole struct
	// with no omitempty and the agent saves config on every token refresh, so a
	// value written here becomes sticky on disk and a later change to the code
	// default would never reach that machine. Every new EPM setting must follow
	// the same zero-value-plus-accessor pattern.
	EPMWindowsTokenType string `json:"epm_windows_token_type"`
	// EPMPolicySignatureMode controls whether Phase 3 policy bundles must
	// carry a valid ed25519 signature. "" means the code default (see
	// GetEPMPolicySignatureMode). Left unset in Load for the same
	// config-stickiness reason as EPMWindowsTokenType above.
	EPMPolicySignatureMode string `json:"epm_policy_signature_mode"`
	// EPMProcessMonitorMode gates Phase 6's process telemetry and
	// terminate-on-violation enforcement: "off" (code default) runs no
	// monitor at all; "observe" runs internal/epm/procmon and records
	// events but never kills anything; "enforce" additionally runs
	// internal/epm/enforce's Tracker/Enforcer. "" means the code default;
	// left unset in Load for the same config-stickiness reason as every
	// other EPM setting above.
	EPMProcessMonitorMode string `json:"epm_process_monitor_mode"`
	// EPMMaxKillsPerMinute is the terminate-on-violation kill-rate limiter
	// (see internal/epm/enforce): once this many kills happen inside a
	// rolling 60s window, enforcement disables itself for the rest of the
	// run (observation continues) rather than risk turning a bad rule into
	// a self-inflicted DoS. 0 means the code default (10); left unset in
	// Load for the same config-stickiness reason as every other EPM
	// setting above.
	EPMMaxKillsPerMinute int `json:"epm_max_kills_per_minute"`
	// EPMBackendTransport selects which internal/epm/transportbe
	// implementation the agent negotiates: "" (code default)/"auto" probes
	// v2 once and falls back to v1 on failure; "v1" and "v2" pin one
	// transport outright, mainly for testing/debugging. "" means the code
	// default; left unset in Load for the same config-stickiness reason as
	// every other EPM setting above.
	EPMBackendTransport string `json:"epm_backend_transport"`
	// EPMAuditRetention bounds how long a synced (already-uploaded)
	// epm_audit_log row is kept locally before epm-db-maintenance deletes
	// it (see main_integration.go's buildEPMDBMaintenanceTask) — closes
	// audit finding DB-3: rows were flagged synced=1 and never deleted,
	// growing the local SQLite file unboundedly on a long-running agent.
	// 0 means the code default (30 days); left unset in Load for the same
	// config-stickiness reason as every other EPM setting above.
	EPMAuditRetention Duration `json:"epm_audit_retention"`
	// EPMGroupedLogUpload switches EPM_ELEVATION_LOG rows from the
	// Uploader's "other" bucket (today's behavior — see uploader.go's
	// buildBatchPayload) into their own "epm" group. Defaults to false
	// (unlike every *bool-guarded EPM flag above, this one's desired
	// default really is false, and a bare bool's zero value already IS
	// false, so this needs no Get accessor or config-stickiness
	// workaround): an existing backend may already depend on
	// EPM_ELEVATION_LOG rows arriving in the "other" group, and
	// log_category is already set per-row regardless (the backend can
	// filter on it today without this flag at all) — this is a nicety to
	// opt into, not a correction to roll out silently.
	EPMGroupedLogUpload bool `json:"epm_grouped_log_upload"`

	// tokenMu guards concurrent token writes (SetTokens) and serialises
	// SaveAtomic. Token refresh runs in its own goroutine while heartbeat,
	// software-sync, and upload tasks read the tokens; without this they race,
	// and two concurrent SaveAtomic calls could collide on the temp file and
	// persist a torn config. Unexported, so it is ignored by JSON (un)marshal.
	tokenMu sync.Mutex
}

// SetTokens atomically replaces the access and refresh tokens in memory.
func (c *Config) SetTokens(accessToken, refreshToken string) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	c.AccessToken = accessToken
	c.RefreshToken = refreshToken
}

// GetAccessToken returns the current access token under lock. Use this from
// concurrent task goroutines rather than reading the field directly.
func (c *Config) GetAccessToken() string {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	return c.AccessToken
}

// GetRefreshToken returns the current refresh token under lock.
func (c *Config) GetRefreshToken() string {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	return c.RefreshToken
}

// GetSoftwareInfoUpdateInterval returns software update interval as time.Duration
func (c *Config) GetSoftwareInfoUpdateInterval() time.Duration {
	if time.Duration(c.UpdateInterval) == 0 {
		return 5 * time.Minute // Default fallback
	}
	return time.Duration(c.UpdateInterval)
}

// GetAutoUpdateInterval returns how often to check for a new release.
func (c *Config) GetAutoUpdateInterval() time.Duration {
	if time.Duration(c.AutoUpdateInterval) == 0 {
		return 1 * time.Hour
	}
	return time.Duration(c.AutoUpdateInterval)
}

// GetAgentInfoUpdateInterval returns how often to push inventory to Supabase.
func (c *Config) GetAgentInfoUpdateInterval() time.Duration {
	if time.Duration(c.AgentInfoUpdateInterval) == 0 {
		return 5 * time.Minute
	}
	return time.Duration(c.AgentInfoUpdateInterval)
}

// GetLogStorageEnabled returns whether log storage is enabled
func (c *Config) GetLogStorageEnabled() bool {
	return c.LogStorageEnabled
}

// GetAuditLogsEnabled returns whether audit logs service is enabled
func (c *Config) GetAuditLogsEnabled() bool {
	return c.AuditLogsEnabled
}

// GetLogFlushInterval returns log collection interval as time.Duration
func (c *Config) GetLogFlushInterval() time.Duration {
	if time.Duration(c.LogFlushInterval) == 0 {
		return 5 * time.Minute // Default to 5 minutes
	}
	return time.Duration(c.LogFlushInterval)
}

// GetServicesUpdateInterval returns how often OS services are collected.
func (c *Config) GetServicesUpdateInterval() time.Duration {
	if time.Duration(c.ServicesUpdateInterval) == 0 {
		return 5 * time.Minute
	}
	return time.Duration(c.ServicesUpdateInterval)
}

// GetEPMPolicySyncInterval returns how often EPM policy rules are synced.
func (c *Config) GetEPMPolicySyncInterval() time.Duration {
	if time.Duration(c.EPMPolicySyncInterval) == 0 {
		return 5 * time.Minute
	}
	return time.Duration(c.EPMPolicySyncInterval)
}

// EPM Windows token types. See GetEPMWindowsTokenType.
const (
	// EPMTokenElevated launches with the requester's linked full-admin token
	// (the other half of UAC's split token). This is the default and the only
	// value that actually grants administrative privilege to an admin user.
	EPMTokenElevated = "elevated"
	// EPMTokenSystem launches as LocalSystem inside the requester's session.
	// It is the only way to run something privileged for a true standard user,
	// who has no linked elevated token at all, but the process runs as SYSTEM
	// rather than as the user: no HKCU, no user profile, no user network
	// identity. Opt-in precisely because those semantics differ.
	EPMTokenSystem = "system"
	// EPMTokenFiltered launches with the requester's own default (UAC-filtered)
	// token. This grants no privilege beyond what the requester already had and
	// exists only as an escape hatch to restore pre-fix behavior.
	EPMTokenFiltered = "filtered"
)

// GetEPMWindowsTokenType returns the configured Windows elevation token type,
// defaulting to EPMTokenElevated.
func (c *Config) GetEPMWindowsTokenType() string {
	if c.EPMWindowsTokenType == "" {
		return EPMTokenElevated
	}
	return c.EPMWindowsTokenType
}

// EPM policy signature modes. See GetEPMPolicySignatureMode. Matches
// epm.SignatureModeOff/Warn/Require exactly — internal/config does not
// import internal/epm (see EPMWindowsTokenType's doc comment for why), so
// these are declared independently and epm.TestSignatureModeMatchesConfigConstants
// guards the two sets against drift.
const (
	EPMSignatureModeOff     = "off"
	EPMSignatureModeWarn    = "warn"
	EPMSignatureModeRequire = "require"
)

// GetEPMPolicySignatureMode returns the configured policy-bundle signature
// mode, defaulting to EPMSignatureModeWarn — every bundle is verified and a
// failure is logged and recorded, but still applies, so an existing backend
// that has not adopted bundle signing keeps working. Flip the code default to
// EPMSignatureModeRequire only once real signing keys are deployed
// fleet-wide (see epm.PolicySigningKeys's doc comment).
func (c *Config) GetEPMPolicySignatureMode() string {
	if c.EPMPolicySignatureMode == "" {
		return EPMSignatureModeWarn
	}
	return c.EPMPolicySignatureMode
}

// EPM process-monitor modes. See GetEPMProcessMonitorMode. Matches
// enforce.ModeOff/Observe/Enforce exactly, declared independently for the
// same reason as EPMSignatureModeOff/Warn/Require above (internal/config
// does not import internal/epm or its subpackages).
const (
	EPMProcessMonitorOff     = "off"
	EPMProcessMonitorObserve = "observe"
	EPMProcessMonitorEnforce = "enforce"
)

// GetEPMProcessMonitorMode returns the configured process-monitor mode,
// defaulting to EPMProcessMonitorOff — no monitor goroutine runs and no
// terminate-on-violation enforcement happens, identical to the agent's
// behavior before Phase 6 existed.
func (c *Config) GetEPMProcessMonitorMode() string {
	if c.EPMProcessMonitorMode == "" {
		return EPMProcessMonitorOff
	}
	return c.EPMProcessMonitorMode
}

// DefaultEPMMaxKillsPerMinute is the terminate-on-violation kill-rate
// limiter's code default. See EPMMaxKillsPerMinute's doc comment.
const DefaultEPMMaxKillsPerMinute = 10

// GetEPMMaxKillsPerMinute returns the configured kill-rate limit, defaulting
// to DefaultEPMMaxKillsPerMinute.
func (c *Config) GetEPMMaxKillsPerMinute() int {
	if c.EPMMaxKillsPerMinute == 0 {
		return DefaultEPMMaxKillsPerMinute
	}
	return c.EPMMaxKillsPerMinute
}

// EPM backend transport modes. See GetEPMBackendTransport. Matches
// transportbe.ModeAuto/V1/V2 exactly, declared independently for the same
// reason as the other EPM mode constants above.
const (
	EPMBackendTransportAuto = "auto"
	EPMBackendTransportV1   = "v1"
	EPMBackendTransportV2   = "v2"
)

// GetEPMBackendTransport returns the configured backend transport mode,
// defaulting to EPMBackendTransportAuto.
func (c *Config) GetEPMBackendTransport() string {
	if c.EPMBackendTransport == "" {
		return EPMBackendTransportAuto
	}
	return c.EPMBackendTransport
}

// DefaultEPMAuditRetention is epm-db-maintenance's code default: how long a
// synced audit row is kept locally after upload. See EPMAuditRetention's
// doc comment.
const DefaultEPMAuditRetention = 30 * 24 * time.Hour

// GetEPMAuditRetention returns the configured EPM audit-log retention
// window, defaulting to DefaultEPMAuditRetention.
func (c *Config) GetEPMAuditRetention() time.Duration {
	if time.Duration(c.EPMAuditRetention) <= 0 {
		return DefaultEPMAuditRetention
	}
	return time.Duration(c.EPMAuditRetention)
}

// GetTaskPollingInterval returns task polling interval as time.Duration
func (c *Config) GetTaskPollingInterval() time.Duration {
	if time.Duration(c.TaskPollingInterval) == 0 {
		return 5 * time.Minute // Default to 5 minutes
	}
	return time.Duration(c.TaskPollingInterval)
}

// Load reads the configuration from the given path. If path is empty, the platform-specific default is used.
func Load(path string) (*Config, error) {
	cfg := &Config{
		Path:                    path,
		UpdateInterval:          Duration(5 * time.Minute), // Default software sync interval
		CurrentVersion:          Version,                   // Use injected version
		AutoUpdate:              true,                      // Enabled by default; updates fetched from Supabase Storage via get_latest_agent_release RPC
		AutoUpdateInterval:      Duration(1 * time.Hour),
		AgentInfoUpdateInterval: Duration(5 * time.Minute),
		TaskPollingInterval:     Duration(5 * time.Minute),
		EnableTaskPolling:       true, // Enabled by default; remote task execution is gated by backend RLS (and, as a follow-up, task-script signing)
		// Supabase configuration — SupabaseURL has no default; it must be set in config.json.
		AgentSecret: "",
		// Log collection configuration
		LogStorageEnabled:      true,                      // Enable log storage by default
		LogFlushInterval:       Duration(5 * time.Minute), // Default to 5 minute collection interval
		SoftwareSyncEnabled:    true,                      // Enable software sync by default
		AuditLogsEnabled:       true,                      // Enable audit logs by default
		ServicesSyncEnabled:    true,                      // Enable services collection by default
		ServicesUpdateInterval: Duration(5 * time.Minute), // Default services collection interval
		// EPMEnabled intentionally left at its zero value (false): EPM is opt-in.
		EPMPolicySyncInterval: Duration(5 * time.Minute), // Default EPM policy sync interval
	}

	if path == "" {
		// Use platform-specific fixed config path
		cfg.Path = GetDefaultConfigPath()
		// Ensure config directory exists
		configDir := filepath.Dir(cfg.Path)
		if err := os.MkdirAll(configDir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create config directory: %v", err)
		}
		// Harden the directory holding the agent's secrets (SYSTEM/Admins-only
		// DACL on Windows; 0700 on Unix). Best-effort: log-and-continue so a
		// permissions failure doesn't prevent the agent from starting.
		if err := secureDir(configDir); err != nil {
			log.Printf("warning: failed to secure config directory %s: %v", configDir, err)
		}
	}

	// Validate and sanitize config path to prevent path traversal
	if cfg.Path != "" {
		// Clean the path to resolve any .. or . components
		cleanPath := filepath.Clean(cfg.Path)
		// Ensure the path is absolute
		if !filepath.IsAbs(cleanPath) {
			absPath, err := filepath.Abs(cleanPath)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve absolute path: %w", err)
			}
			cleanPath = absPath
		}
		cfg.Path = cleanPath
	}

	if _, err := os.Stat(cfg.Path); err == nil {
		data, err := os.ReadFile(cfg.Path)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}

	// Reconcile the reported version with the version actually running. The
	// compiled-in Version (injected via -ldflags) is the authoritative source of
	// truth for what binary is executing; the persisted current_version can drift
	// (e.g. if a self-update swap failed after the version was written). Asserting
	// the real version here means a failed update is detected and retried on the
	// next check instead of the agent silently reporting a version it isn't
	// running. See internal/updater.CheckAndApply.
	cfg.CurrentVersion = Version

	// Ensure DeviceID exists
	if cfg.DeviceID == "" {
		cfg.DeviceID = generateDeviceID()
	}

	// Ensure AgentID exists
	if cfg.AgentID == "" {
		cfg.AgentID = generateDeviceID()
	}

	return cfg, nil
}

func generateDeviceID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp if random fails
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// Save persists the current configuration to disk at the configured path.
func (c *Config) Save() error {
	dir := filepath.Dir(c.Path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}

	// Validate config before saving
	if err := c.validateConfig(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	// #nosec G117 - Config includes AccessToken for persistence, saved with secure permissions
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	// Save with secure permissions (0600 for sensitive config)
	return os.WriteFile(c.Path, data, 0600)
}

// SaveAtomic saves config atomically to prevent corruption. It serialises with
// token writes and uses a unique temp file per call so concurrent saves cannot
// collide on a fixed ".tmp" path and persist a torn/interleaved config.
func (c *Config) SaveAtomic() error {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	dir := filepath.Dir(c.Path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}

	// Validate config before saving
	if err := c.validateConfig(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	// #nosec G117 - Config includes AccessToken for persistence, saved with secure permissions
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	// Unique temp file in the same directory (so the rename stays on one device).
	tmp, err := os.CreateTemp(dir, "config-*.tmp")
	if err != nil {
		return err
	}
	tempPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		if removeErr := os.Remove(tempPath); removeErr != nil && !os.IsNotExist(removeErr) {
			log.Printf("failed to remove temp file %s: %v", tempPath, removeErr)
		}
	}

	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	// Restrict to owner read/write (effective on Unix; Windows ACLs are applied
	// to the final file via secureConfigFile below).
	if err := tmp.Chmod(0600); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	// Atomic rename
	if err := os.Rename(tempPath, c.Path); err != nil {
		if removeErr := os.Remove(tempPath); removeErr != nil {
			log.Printf("failed to remove temp file %s: %v", tempPath, removeErr)
		}
		return err
	}

	// Harden on-disk permissions for the secrets file (no-op on Unix where the
	// 0600 mode already applies; sets an explicit DACL on Windows).
	if err := secureConfigFile(c.Path); err != nil {
		log.Printf("warning: failed to secure config file permissions: %v", err)
	}

	return nil
}

// validateConfig performs comprehensive validation
func (c *Config) validateConfig() error {
	if c.SupabaseURL == "" {
		return fmt.Errorf("supabase_url is required")
	}

	if c.SupabaseKey == "" {
		return fmt.Errorf("supabase_key is required")
	}

	if c.DeviceID == "" {
		return fmt.Errorf("device_id is required")
	}

	// Validate URL format
	if !isValidURL(c.SupabaseURL) {
		return fmt.Errorf("supabase_url is not a valid URL")
	}

	// Validate intervals
	if c.GetSoftwareInfoUpdateInterval() <= 0 {
		return fmt.Errorf("update_interval must be positive")
	}

	if c.GetLogFlushInterval() <= 0 {
		return fmt.Errorf("log_flush_interval must be positive")
	}

	if c.GetTaskPollingInterval() <= 0 {
		return fmt.Errorf("task_polling_interval must be positive")
	}

	// EPM settings. Validated even when EPM is disabled so a typo surfaces at
	// startup rather than the first time someone flips enable_epm on.
	if c.GetEPMPolicySyncInterval() <= 0 {
		return fmt.Errorf("epm_policy_sync_interval must be positive")
	}

	switch c.GetEPMWindowsTokenType() {
	case EPMTokenElevated, EPMTokenSystem, EPMTokenFiltered:
	default:
		return fmt.Errorf("epm_windows_token_type must be one of %q, %q, %q (got %q)",
			EPMTokenElevated, EPMTokenSystem, EPMTokenFiltered, c.EPMWindowsTokenType)
	}

	switch c.GetEPMPolicySignatureMode() {
	case EPMSignatureModeOff, EPMSignatureModeWarn, EPMSignatureModeRequire:
	default:
		return fmt.Errorf("epm_policy_signature_mode must be one of %q, %q, %q (got %q)",
			EPMSignatureModeOff, EPMSignatureModeWarn, EPMSignatureModeRequire, c.EPMPolicySignatureMode)
	}

	switch c.GetEPMProcessMonitorMode() {
	case EPMProcessMonitorOff, EPMProcessMonitorObserve, EPMProcessMonitorEnforce:
	default:
		return fmt.Errorf("epm_process_monitor_mode must be one of %q, %q, %q (got %q)",
			EPMProcessMonitorOff, EPMProcessMonitorObserve, EPMProcessMonitorEnforce, c.EPMProcessMonitorMode)
	}

	if c.EPMMaxKillsPerMinute < 0 {
		return fmt.Errorf("epm_max_kills_per_minute must not be negative (got %d)", c.EPMMaxKillsPerMinute)
	}

	switch c.GetEPMBackendTransport() {
	case EPMBackendTransportAuto, EPMBackendTransportV1, EPMBackendTransportV2:
	default:
		return fmt.Errorf("epm_backend_transport must be one of %q, %q, %q (got %q)",
			EPMBackendTransportAuto, EPMBackendTransportV1, EPMBackendTransportV2, c.EPMBackendTransport)
	}

	return nil
}

// isValidURL validates that s is a parseable http/https URL with a host.
func isValidURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// ValidateConfiguration performs comprehensive validation
func (c *Config) ValidateConfiguration() error {
	return c.validateConfig()
}
