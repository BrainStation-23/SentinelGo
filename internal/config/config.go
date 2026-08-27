package config

import (
	"bytes"
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

// defaultConfigPath resolves the path Load uses when it is given none.
//
// It is a variable, not a direct call, purely so tests can redirect the
// empty-path branch at a temp directory (see export_test.go). Production
// behaviour is unchanged: nothing outside a test ever reassigns it, so Load
// resolves exactly what GetDefaultConfigPath returns.
//
// The branch is worth being able to test. It is the one that creates and
// hardens the directory holding the agent's credentials, and testing it by
// calling Load("") for real meant reading the live C:\SentinelGo config on the
// developer's own machine — which fails outright on a host where that
// directory is not writable by the test user, and reads real credentials on
// one where it is.
var defaultConfigPath = GetDefaultConfigPath

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
	Path           string   `json:"-"`               // Path to the config file
	UpdateInterval Duration `json:"update_interval"` // Software-sync scheduler tick (supports both "5m0s" and numeric formats)

	// SoftwareCollectInterval is the minimum gap between full software scans,
	// which is the expensive part; the scheduler tick above only decides how
	// often the agent CHECKS whether a scan is due. Zero means the 6h default;
	// negative disables the gate and scans on every tick.
	SoftwareCollectInterval Duration `json:"software_collect_interval"`
	// SoftwareResendInterval is how long an unchanged inventory may go without
	// a refresh upload. Zero means the 24h default.
	SoftwareResendInterval  Duration `json:"software_resend_interval"`
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
	SupabaseURL string `json:"supabase_url"` // Supabase project URL
	SupabaseKey string `json:"supabase_key"` // Supabase anon/public API key (for apikey header)
	AgentSecret string `json:"agent_secret"` // Agent secret for authentication

	// CredentialProtection selects how access_token, refresh_token and
	// agent_secret are stored at rest: "auto" (default) uses the best mechanism
	// the platform offers, "off" stores plaintext as before. See
	// internal/config/credential.go and docs/security/credential-storage.md.
	CredentialProtection string `json:"credential_protection,omitempty"`
	AgentID              string `json:"agent_id"`      // Custom agent UUID field (maps to agent_uuid database column)
	AccessToken          string `json:"access_token"`  // JWT access token from Supabase
	RefreshToken         string `json:"refresh_token"` // JWT refresh token from Supabase
	// Log collection configuration
	LogStorageEnabled bool     `json:"log_storage_enabled"` // Enable/disable log storage
	LogFlushInterval  Duration `json:"log_flush_interval"`  // Log collection/upload interval (supports both "5m0s" and numeric formats)
	// Service configuration
	SoftwareSyncEnabled    bool     `json:"software_sync_enabled"`    // Enable software synchronization
	AuditLogsEnabled       bool     `json:"audit_logs_enabled"`       // Enable audit logs service
	EdgeFunctionURL        string   `json:"edge_function_url"`        // Edge Function URL for software data
	ServicesSyncEnabled    bool     `json:"services_sync_enabled"`    // Enable OS services collection
	ServicesUpdateInterval Duration `json:"services_update_interval"` // How often to collect OS services (default 5m)

	// Telemetry layer configuration.
	//
	// The telemetry layer is additive: it runs alongside the existing inventory,
	// software and services pipelines without altering them. It stays disabled by
	// default until collectors and the backend contract are in place.
	TelemetryEnabled         bool     `json:"telemetry_enabled"`          // Enable the enterprise telemetry layer
	TelemetryCollectInterval Duration `json:"telemetry_collect_interval"` // How often the telemetry task runs (default 15m)
	TelemetryQueueMaxRows    int      `json:"telemetry_queue_max_rows"`   // Outbound queue row cap (default 5000)
	TelemetryQueueMaxBytes   int64    `json:"telemetry_queue_max_bytes"`  // Outbound queue byte cap (default 64MB)
	TelemetryQueueMaxAge     Duration `json:"telemetry_queue_max_age"`    // Outbound queue age cap (default 72h)

	// TelemetryGzipEnabled compresses telemetry request bodies with gzip.
	//
	// OFF by default and it must stay off until the SentinelOps backend
	// confirms it decompresses request bodies. If it does not, every telemetry
	// upload becomes a 4xx, which the sender retains and dead-letters after
	// five attempts — the data is not lost, but nothing is delivered either.
	// See docs/backend/backend-compatibility-checklist.md.
	TelemetryGzipEnabled bool `json:"telemetry_gzip_enabled"`

	// Audit-log queue retention. The audit queue was originally unbounded and
	// grew until the endpoint's disk filled whenever uploads stopped; these are
	// the same three axes the telemetry outbound queue uses. Zero on any axis
	// means "use the shipped default", never "unbounded" — see
	// store.AuditLogLimits. The row cap default is an order of magnitude higher
	// than telemetry's because audit rows are individual OS event records
	// rather than batched telemetry messages.
	AuditQueueMaxRows  int      `json:"audit_queue_max_rows"`  // Audit queue row cap (default 50000)
	AuditQueueMaxBytes int64    `json:"audit_queue_max_bytes"` // Audit queue byte cap (default 64MB)
	AuditQueueMaxAge   Duration `json:"audit_queue_max_age"`   // Audit queue age cap (default 72h)

	// Event telemetry (change detection) configuration.
	//
	// Shipped disabled. An existing config.json that predates these fields
	// parses unchanged and the agent behaves exactly as it did before: the
	// zero value of TelemetryEventsEnabled is false, and every interval below
	// falls back to a vetted default through its Get* accessor rather than to
	// zero.
	//
	// TelemetryEventsEnabled turns on comparison of already-collected values
	// against a persisted baseline. It performs no collection of its own, so
	// enabling it costs effectively nothing on a stable endpoint.
	TelemetryEventsEnabled bool `json:"telemetry_events_enabled"`
	// TelemetryEventDebounce is how long a Normal-priority change must persist
	// before it is reported. Zero means "confirm on the next successful
	// cycle", which is the intended default. Critical and high-priority
	// changes are never debounced.
	TelemetryEventDebounce Duration `json:"telemetry_event_debounce"`
	// TelemetryEventCooldown is the minimum gap between two events for the
	// same watched value (default 10m).
	TelemetryEventCooldown Duration `json:"telemetry_event_cooldown"`
	// TelemetryEventFlapWindow is the period over which repeated changes to
	// one value are counted (default 1h).
	TelemetryEventFlapWindow Duration `json:"telemetry_event_flap_window"`
	// TelemetryEventFlapThreshold is how many changes inside the flapping
	// window collapse into a single aggregate event instead of one each
	// (default 4).
	TelemetryEventFlapThreshold int `json:"telemetry_event_flap_threshold"`

	// ProcessesCollectCmdline enables process command-line capture. Off by
	// default and deliberately separate from process collection itself: command
	// lines routinely carry tokens, passwords and connection strings passed as
	// arguments, so capturing them is its own privacy decision.
	ProcessesCollectCmdline bool `json:"processes_collect_cmdline"`
	// IncludeBuiltinScheduledTasks includes OS-shipped scheduled tasks on Windows.
	// Off by default: they are the large majority of the list and rarely of
	// interest for enterprise inventory.
	IncludeBuiltinScheduledTasks bool `json:"include_builtin_scheduled_tasks"`
	// CollectRoutingTable enables full routing-table collection, which is
	// detailed telemetry rather than basic network inventory.
	CollectRoutingTable bool `json:"collect_routing_table"`

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

// GetSoftwareInfoUpdateInterval returns how often the software-sync scheduler
// task ticks.
//
// This remains the legacy `update_interval` key with its legacy five-minute
// fallback, deliberately: it is the scheduler tick, and an existing config file
// on disk already carries a value for it. What changed is that a tick no longer
// implies a scan — the expensive collection is gated separately by
// GetSoftwareCollectInterval, so an endpoint upgrading with "5m0s" already
// written into its config stops scanning every five minutes without anyone
// having to edit it.
func (c *Config) GetSoftwareInfoUpdateInterval() time.Duration {
	if time.Duration(c.UpdateInterval) == 0 {
		return 5 * time.Minute // Default fallback
	}
	return time.Duration(c.UpdateInterval)
}

// GetSoftwareCollectInterval returns the minimum gap between full software
// scans, defaulting to software.DefaultCollectInterval (6h).
//
// Zero means "use the default"; a negative value disables the gate and restores
// scan-on-every-tick, which is available deliberately for anyone who needs it.
func (c *Config) GetSoftwareCollectInterval() time.Duration {
	if c.SoftwareCollectInterval == 0 {
		return 6 * time.Hour
	}
	return time.Duration(c.SoftwareCollectInterval)
}

// GetSoftwareResendInterval returns how long an unchanged software inventory
// may go without being re-sent, defaulting to 24h.
//
// This is the reconcile clock: it guarantees the backend eventually receives a
// refresh after a manual database fix, independently of whether anything on the
// endpoint changed.
func (c *Config) GetSoftwareResendInterval() time.Duration {
	if time.Duration(c.SoftwareResendInterval) <= 0 {
		return 24 * time.Hour
	}
	return time.Duration(c.SoftwareResendInterval)
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

// GetTelemetryCollectInterval returns how often the telemetry task runs,
// defaulting to 15 minutes when unset or invalid.
func (c *Config) GetTelemetryCollectInterval() time.Duration {
	if time.Duration(c.TelemetryCollectInterval) <= 0 {
		return 15 * time.Minute
	}
	return time.Duration(c.TelemetryCollectInterval)
}

// GetAuditQueueMaxAge returns the configured audit-queue age cap.
//
// These three getters deliberately return the raw configured value, including
// zero, rather than substituting a default here. The defaults live in
// store.AuditLogLimits.withDefaults so there is exactly one place that decides
// them; duplicating them in this package would let the two drift and leave
// nobody sure which one an endpoint actually applied. It also keeps config free
// of a dependency on store.
func (c *Config) GetAuditQueueMaxAge() time.Duration { return time.Duration(c.AuditQueueMaxAge) }

// GetAuditQueueMaxRows returns the configured audit-queue row cap; see
// GetAuditQueueMaxAge for why zero is passed through.
func (c *Config) GetAuditQueueMaxRows() int { return c.AuditQueueMaxRows }

// GetAuditQueueMaxBytes returns the configured audit-queue byte cap; see
// GetAuditQueueMaxAge for why zero is passed through.
func (c *Config) GetAuditQueueMaxBytes() int64 { return c.AuditQueueMaxBytes }

// GetTelemetryQueueMaxAge returns the outbound queue age cap, defaulting to 72h.
func (c *Config) GetTelemetryQueueMaxAge() time.Duration {
	if time.Duration(c.TelemetryQueueMaxAge) <= 0 {
		return 72 * time.Hour
	}
	return time.Duration(c.TelemetryQueueMaxAge)
}

// GetTelemetryQueueMaxRows returns the outbound queue row cap, defaulting to 5000.
func (c *Config) GetTelemetryQueueMaxRows() int {
	if c.TelemetryQueueMaxRows <= 0 {
		return 5000
	}
	return c.TelemetryQueueMaxRows
}

// GetTelemetryQueueMaxBytes returns the outbound queue byte cap, defaulting to 64MB.
func (c *Config) GetTelemetryQueueMaxBytes() int64 {
	if c.TelemetryQueueMaxBytes <= 0 {
		return 64 * 1024 * 1024
	}
	return c.TelemetryQueueMaxBytes
}

// GetTelemetryEventDebounce returns the confirmation delay for Normal-priority
// change events.
//
// Zero is a MEANINGFUL value here, not an unset one: it selects the default
// "confirm on the next successful cycle" rule. Only a negative value is
// coerced, and coercing it to zero keeps that rule rather than inventing a
// duration nobody asked for.
func (c *Config) GetTelemetryEventDebounce() time.Duration {
	if time.Duration(c.TelemetryEventDebounce) < 0 {
		return 0
	}
	return time.Duration(c.TelemetryEventDebounce)
}

// GetTelemetryEventCooldown returns the minimum gap between two events for one
// watched value, defaulting to 10 minutes.
func (c *Config) GetTelemetryEventCooldown() time.Duration {
	if time.Duration(c.TelemetryEventCooldown) <= 0 {
		return 10 * time.Minute
	}
	return time.Duration(c.TelemetryEventCooldown)
}

// GetTelemetryEventFlapWindow returns the flapping window, defaulting to 1 hour.
func (c *Config) GetTelemetryEventFlapWindow() time.Duration {
	if time.Duration(c.TelemetryEventFlapWindow) <= 0 {
		return 1 * time.Hour
	}
	return time.Duration(c.TelemetryEventFlapWindow)
}

// GetTelemetryEventFlapThreshold returns how many changes inside the flapping
// window collapse into one aggregate event, defaulting to 4.
//
// A configured 1 is rejected rather than honoured: it would classify the very
// first change to any value as flapping, which silently replaces every real
// event with an aggregate one.
func (c *Config) GetTelemetryEventFlapThreshold() int {
	if c.TelemetryEventFlapThreshold <= 1 {
		return 4
	}
	return c.TelemetryEventFlapThreshold
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
		UpdateInterval:          Duration(5 * time.Minute), // software-sync scheduler tick
		SoftwareCollectInterval: Duration(6 * time.Hour),   // minimum gap between full scans
		SoftwareResendInterval:  Duration(24 * time.Hour),  // refresh cadence for an unchanged list
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
		// Telemetry layer: off until collectors and the backend contract land.
		TelemetryEnabled:         false,
		TelemetryCollectInterval: Duration(15 * time.Minute),
		TelemetryQueueMaxRows:    5000,
		TelemetryQueueMaxBytes:   64 * 1024 * 1024,
		TelemetryQueueMaxAge:     Duration(72 * time.Hour),
		// Change detection stays off until it is explicitly switched on.
		TelemetryEventsEnabled:      false,
		TelemetryEventDebounce:      0,
		TelemetryEventCooldown:      Duration(10 * time.Minute),
		TelemetryEventFlapWindow:    Duration(1 * time.Hour),
		TelemetryEventFlapThreshold: 4,
		// Privacy-sensitive collection stays opt-in.
		ProcessesCollectCmdline:      false,
		IncludeBuiltinScheduledTasks: false,
		CollectRoutingTable:          false,
	}

	if path == "" {
		// Use platform-specific fixed config path
		cfg.Path = defaultConfigPath()
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
		// Strip a leading UTF-8 BOM before parsing. encoding/json rejects one,
		// but Windows tooling adds it silently — PowerShell 5.1's Set-Content
		// and Out-File -Encoding UTF8 both do. The resulting failure is far
		// worse than it looks: Load returns an error, main exits via log.Fatalf
		// before svc.Run calls StartServiceCtrlDispatcher, and the SCM reports
		// a generic 1053 with events 7000/7009 whose "30000 milliseconds" text
		// is a fixed string, not a measurement. That reads as a startup timeout
		// and sends you hunting for slow initialisation that isn't there.
		data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
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

	// Convert stored credentials to plaintext for use in memory. Plaintext
	// values on disk pass straight through, which is what lets an existing
	// installation upgrade onto protected storage without re-registering.
	//
	// A failure here is reported but is NOT fatal: the agent starts with empty
	// credentials and takes its existing unauthenticated path, which is
	// recoverable. Refusing to load would instead stop the service entirely and
	// take the audit-log and update paths down with it — for a fault whose most
	// likely cause is a config file copied from another machine, exactly what
	// machine-bound protection is meant to make harmless.
	if err := cfg.unprotectSecrets(); err != nil {
		log.Printf("[config] %v", err)
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

	// Credentials are protected on the way out; the live config is never
	// mutated. See Config.marshalProtected.
	data, err := c.marshalProtected()
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

	// Credentials are protected on the way out; see the same note in Save.
	data, err := c.marshalProtected()
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

// SecureConfigFile sets secure permissions on config file
func (c *Config) SecureConfigFile() error {
	// Set file permissions to 0600 (read/write for owner only)
	return os.Chmod(c.Path, 0600)
}
