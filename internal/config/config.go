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
	GitHubOwner             string   `json:"github_owner"`
	GitHubRepo              string   `json:"github_repo"`
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
	SoftwareSyncEnabled bool   `json:"software_sync_enabled"` // Enable software synchronization
	AuditLogsEnabled    bool   `json:"audit_logs_enabled"`    // Enable audit logs service
	EdgeFunctionURL     string `json:"edge_function_url"`     // Edge Function URL for software data
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
		return 24 * time.Hour
	}
	return time.Duration(c.AutoUpdateInterval)
}

// GetAgentInfoUpdateInterval returns how often to push inventory to Supabase.
func (c *Config) GetAgentInfoUpdateInterval() time.Duration {
	if time.Duration(c.AgentInfoUpdateInterval) == 0 {
		return time.Hour
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
		GitHubOwner:             "BrainStation-23",
		GitHubRepo:              "SentinelGo",
		CurrentVersion:          Version, // Use injected version
		AutoUpdate:              true,    // Disabled by default for safety
		AutoUpdateInterval:      Duration(24 * time.Hour),
		AgentInfoUpdateInterval: Duration(time.Hour),
		TaskPollingInterval:     Duration(5 * time.Minute),
		EnableTaskPolling:       true, // Disabled by default for safety
		// Supabase configuration — SupabaseURL has no default; it must be set in config.json.
		AgentSecret: "",
		// Log collection configuration
		LogStorageEnabled:   true,                      // Enable log storage by default
		LogFlushInterval:    Duration(5 * time.Minute), // Default to 5 minute collection interval
		SoftwareSyncEnabled: true,                      // Enable software sync by default
		AuditLogsEnabled:    true,                      // Enable audit logs by default
	}

	if path == "" {
		// Use platform-specific fixed config path
		cfg.Path = GetDefaultConfigPath()
		// Ensure config directory exists
		configDir := filepath.Dir(cfg.Path)
		if err := os.MkdirAll(configDir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create config directory: %v", err)
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

// SaveAtomic saves config atomically to prevent corruption
func (c *Config) SaveAtomic() error {
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

	// Create temporary file
	tempPath := c.Path + ".tmp"
	if err := os.WriteFile(tempPath, data, 0600); err != nil {
		return err
	}

	// Atomic rename
	if err := os.Rename(tempPath, c.Path); err != nil {
		if removeErr := os.Remove(tempPath); removeErr != nil {
			log.Printf("failed to remove temp file %s: %v", tempPath, removeErr)
		}
		return err
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
