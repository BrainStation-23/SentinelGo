package config

import (
	"encoding/json"
	"fmt"
	"time"
)

// Floors and ceiling for the intervals the server may set (#466). They match
// the limits sentinel-ops#902 enforces when an admin saves the settings, and
// keep a bad value from making the agent hammer the server.
const (
	MinServerTaskPollingInterval = 10 * time.Second
	MinServerLogFlushInterval    = 30 * time.Second
	MinServerSyncInterval        = 5 * time.Minute
	MaxServerInterval            = 24 * time.Hour
)

// ServerConfig is the last agent-settings block the server sent in an RPC
// reply ("config", sentinel-ops#902) and the agent applied. It is kept apart
// from the local fields so the local kill switch (audit_logs_enabled: false)
// is never overwritten, and persisted in config.json so a restart keeps it.
// A zero interval or nil switch means "not set by the server".
type ServerConfig struct {
	AuditLogsEnabled     *bool    `json:"audit_logs_enabled,omitempty"`
	TaskPollingInterval  Duration `json:"task_polling_interval,omitempty"`
	LogFlushInterval     Duration `json:"log_flush_interval,omitempty"`
	SoftwareSyncInterval Duration `json:"software_sync_interval,omitempty"`
	ServicesSyncInterval Duration `json:"services_sync_interval,omitempty"`
	Version              int64    `json:"version"`
}

// serverConfigWire is the block as the server sends it. Unknown members are
// ignored; an interval that doesn't parse is treated as not set.
type serverConfigWire struct {
	AuditLogsEnabled     *bool  `json:"audit_logs_enabled"`
	TaskPollingInterval  string `json:"task_polling_interval"`
	LogFlushInterval     string `json:"log_flush_interval"`
	SoftwareSyncInterval string `json:"software_sync_interval"`
	ServicesSyncInterval string `json:"services_sync_interval"`
	Version              int64  `json:"version"`
}

// EffectiveSettings are the server-controllable values the agent runs with.
type EffectiveSettings struct {
	AuditLogsEnabled     bool
	TaskPollingInterval  time.Duration
	LogFlushInterval     time.Duration
	SoftwareSyncInterval time.Duration
	ServicesSyncInterval time.Duration
}

// ServerConfigChange reports what ApplyServerConfig did.
type ServerConfigChange struct {
	// Applied is false when the block was ignored (not newer than the one
	// already applied); the other fields are then zero.
	Applied bool
	Version int64
	Before  EffectiveSettings
	After   EffectiveSettings
	// Clamped names the intervals that were outside their limits.
	Clamped []string
}

// clampInterval bounds d to [floor, MaxServerInterval]; 0 stays 0 (not set).
func clampInterval(d, floor time.Duration) time.Duration {
	switch {
	case d <= 0:
		return 0
	case d < floor:
		return floor
	case d > MaxServerInterval:
		return MaxServerInterval
	}
	return d
}

// parseServerInterval parses one interval and clamps it. clamped is true when
// the value was out of range; a value that doesn't parse returns 0.
func parseServerInterval(s string, floor time.Duration) (d time.Duration, clamped bool) {
	if s == "" {
		return 0, false
	}
	v, err := time.ParseDuration(s)
	if err != nil || v <= 0 {
		return 0, false
	}
	d = clampInterval(v, floor)
	return d, d != v
}

// ParseServerConfig decodes a "config" member into a ServerConfig with every
// interval clamped, and names the intervals it clamped.
func ParseServerConfig(raw []byte) (ServerConfig, []string, error) {
	var w serverConfigWire
	if err := json.Unmarshal(raw, &w); err != nil {
		return ServerConfig{}, nil, fmt.Errorf("parse server config: %w", err)
	}
	sc := ServerConfig{AuditLogsEnabled: w.AuditLogsEnabled, Version: w.Version}
	var clamped []string
	for _, f := range []struct {
		name  string
		in    string
		floor time.Duration
		out   *Duration
	}{
		{"task_polling_interval", w.TaskPollingInterval, MinServerTaskPollingInterval, &sc.TaskPollingInterval},
		{"log_flush_interval", w.LogFlushInterval, MinServerLogFlushInterval, &sc.LogFlushInterval},
		{"software_sync_interval", w.SoftwareSyncInterval, MinServerSyncInterval, &sc.SoftwareSyncInterval},
		{"services_sync_interval", w.ServicesSyncInterval, MinServerSyncInterval, &sc.ServicesSyncInterval},
	} {
		d, c := parseServerInterval(f.in, f.floor)
		*f.out = Duration(d)
		if c {
			clamped = append(clamped, f.name)
		}
	}
	return sc, clamped, nil
}

// ApplyServerConfig applies a "config" member from an RPC reply when its
// version is newer than the one already applied, and reports the effective
// values before and after. It changes memory only; the caller persists with
// SaveAtomic. Safe for concurrent use.
func (c *Config) ApplyServerConfig(raw []byte) (ServerConfigChange, error) {
	sc, clamped, err := ParseServerConfig(raw)
	if err != nil {
		return ServerConfigChange{}, err
	}

	// Lock order: tokenMu (which SaveAtomic holds while marshalling the
	// ServerConfig field), then serverMu (which the getters take).
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	c.serverMu.Lock()
	defer c.serverMu.Unlock()

	if c.ServerConfig != nil && sc.Version <= c.ServerConfig.Version {
		return ServerConfigChange{}, nil
	}
	before := c.effectiveLocked()
	c.ServerConfig = &sc
	return ServerConfigChange{
		Applied: true,
		Version: sc.Version,
		Before:  before,
		After:   c.effectiveLocked(),
		Clamped: clamped,
	}, nil
}

// Effective returns the server-controllable values the agent runs with.
func (c *Config) Effective() EffectiveSettings {
	c.serverMu.RLock()
	defer c.serverMu.RUnlock()
	return c.effectiveLocked()
}

// AuditLogsDisabledByServer reports whether the server, not the local
// config, is what keeps audit logs off.
func (c *Config) AuditLogsDisabledByServer() bool {
	c.serverMu.RLock()
	defer c.serverMu.RUnlock()
	return c.AuditLogsEnabled && !c.serverAuditLogsLocked()
}

// ServerConfigVersion returns the version of the applied server block, 0
// when none was applied.
func (c *Config) ServerConfigVersion() int64 {
	c.serverMu.RLock()
	defer c.serverMu.RUnlock()
	if c.ServerConfig == nil {
		return 0
	}
	return c.ServerConfig.Version
}

func (c *Config) effectiveLocked() EffectiveSettings {
	return EffectiveSettings{
		AuditLogsEnabled:     c.AuditLogsEnabled && c.serverAuditLogsLocked(),
		TaskPollingInterval:  c.serverIntervalLocked(func(s *ServerConfig) Duration { return s.TaskPollingInterval }, MinServerTaskPollingInterval, localOr(c.TaskPollingInterval, 5*time.Minute)),
		LogFlushInterval:     c.serverIntervalLocked(func(s *ServerConfig) Duration { return s.LogFlushInterval }, MinServerLogFlushInterval, localOr(c.LogFlushInterval, 5*time.Minute)),
		SoftwareSyncInterval: c.serverIntervalLocked(func(s *ServerConfig) Duration { return s.SoftwareSyncInterval }, MinServerSyncInterval, localOr(c.UpdateInterval, 5*time.Minute)),
		ServicesSyncInterval: c.serverIntervalLocked(func(s *ServerConfig) Duration { return s.ServicesSyncInterval }, MinServerSyncInterval, localOr(c.ServicesUpdateInterval, 5*time.Minute)),
	}
}

// serverAuditLogsLocked is the server's switch; true when it sent none.
func (c *Config) serverAuditLogsLocked() bool {
	if c.ServerConfig == nil || c.ServerConfig.AuditLogsEnabled == nil {
		return true
	}
	return *c.ServerConfig.AuditLogsEnabled
}

// serverIntervalLocked returns the server's interval (clamped again, in case
// config.json was edited by hand) or local when the server set none.
func (c *Config) serverIntervalLocked(get func(*ServerConfig) Duration, floor, local time.Duration) time.Duration {
	if c.ServerConfig == nil {
		return local
	}
	if d := clampInterval(time.Duration(get(c.ServerConfig)), floor); d > 0 {
		return d
	}
	return local
}

func localOr(d Duration, def time.Duration) time.Duration {
	if time.Duration(d) == 0 {
		return def
	}
	return time.Duration(d)
}
