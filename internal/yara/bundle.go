package yara

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
)

// Errors Decode returns. The ruleset sync (#411) reports the first two as
// the status states too_large and unsupported_schema and keeps the last
// good bundle for all of them.
var (
	ErrTooLarge          = errors.New("yara: bundle over the contract's size limits")
	ErrUnsupportedSchema = errors.New("yara: unsupported bundle schema_version")
	ErrInvalidBundle     = errors.New("yara: invalid bundle")
)

// Bundle is the device's ruleset bundle (schema_version 1, contract §2).
// Unknown keys are ignored.
type Bundle struct {
	SchemaVersion int `json:"schema_version"`
	// Version is opaque (the backend sends the SHA-256 of the bundle JSON).
	Version string `json:"version"`
	// Enabled false: stop scans in progress, delete compiled rules, keep the
	// event queue. A disabled bundle has no rulesets or schedules.
	Enabled   bool       `json:"enabled"`
	Engine    Engine     `json:"engine"`
	Rulesets  []Ruleset  `json:"rulesets"`
	Schedules []Schedule `json:"schedules"`
	Limits    Limits     `json:"limits"`
	Evidence  Evidence   `json:"evidence"`
	// OnWrite is contract v1.1 (#418): scan files as they are written into
	// watched folders. nil (an older backend) means off.
	OnWrite *OnWrite `json:"on_write,omitempty"`
}

// OnWrite configures on-write scanning (contract v1.1, #418).
type OnWrite struct {
	Enabled bool `json:"enabled"`
	// Paths are the folders watched on each OS, recursively. An empty list
	// for an OS means the agent's on-write defaults (walk.OnWriteRoots),
	// not "off": off is Enabled false.
	Paths      OSPaths `json:"paths"`
	Exclusions OSPaths `json:"exclusions"`
	// RulesetIDs nil means every ruleset in the bundle.
	RulesetIDs []string `json:"ruleset_ids"`
}

// MaxOnWritePaths bounds on_write's paths and exclusions per OS.
const MaxOnWritePaths = 64

// OnWriteEnabled reports whether the bundle asks for on-write scanning.
func (b *Bundle) OnWriteEnabled() bool {
	return b != nil && b.Enabled && b.OnWrite != nil && b.OnWrite.Enabled
}

// Engine names the engine the rules were validated with.
type Engine struct {
	Name       string `json:"name"`
	MinVersion string `json:"min_version"`
}

// Ruleset is one published ruleset revision. Its source is the Storage
// object StoragePath, which the agent rejects unless its SHA-256 and size
// match.
type Ruleset struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Revision    int      `json:"revision"`
	StoragePath string   `json:"storage_path"`
	SHA256      string   `json:"sha256"`
	Size        int64    `json:"size"`
	Severity    string   `json:"severity"`
	Tags        []string `json:"tags"`
}

// Schedule is a recurring scan.
type Schedule struct {
	ID     string `json:"id"`
	Preset string `json:"preset"`
	// Paths: an empty list for an OS means the preset's defaults (#413);
	// for custom it means "don't scan on this OS".
	Paths         OSPaths `json:"paths"`
	Exclusions    OSPaths `json:"exclusions"`
	EveryHours    int     `json:"every_hours"`
	JitterMinutes int     `json:"jitter_minutes"`
	// RulesetIDs nil means every ruleset in the bundle.
	RulesetIDs []string `json:"ruleset_ids"`
}

// OSPaths is a list of paths per OS.
type OSPaths struct {
	Windows []string `json:"windows"`
	Darwin  []string `json:"darwin"`
	Linux   []string `json:"linux"`
}

// For returns the list for goos (runtime.GOOS), nil for any other OS.
func (p OSPaths) For(goos string) []string {
	switch goos {
	case "windows":
		return p.Windows
	case "darwin":
		return p.Darwin
	case "linux":
		return p.Linux
	}
	return nil
}

// Limits are the per-scan guardrails (#413).
type Limits struct {
	MaxFileBytes         int64 `json:"max_file_bytes"`
	PerFileTimeoutMS     int   `json:"per_file_timeout_ms"`
	MaxCPUPercent        int   `json:"max_cpu_percent"`
	SkipOnBattery        bool  `json:"skip_on_battery"`
	IncludeNetworkMounts bool  `json:"include_network_mounts"`
	IncludeRemovable     bool  `json:"include_removable"`
	MaxFilesPerScan      int   `json:"max_files_per_scan"`
	MaxScanMinutes       int   `json:"max_scan_minutes"`
}

// DefaultLimits are the contract's safe values, used for any limit the
// bundle leaves out or sends out of range.
func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes:     100 << 20,
		PerFileTimeoutMS: 10_000,
		MaxCPUPercent:    25,
		SkipOnBattery:    true,
		MaxFilesPerScan:  500_000,
		MaxScanMinutes:   240,
	}
}

// Evidence says how much of a match the agent reports.
type Evidence struct {
	// PathMode full sends the path; hashed sends only its SHA-256 and the
	// file name's extension.
	PathMode string `json:"path_mode"`
}

// HashPaths reports whether paths must be hashed. Anything but "full" is
// treated as hashed, so an unknown mode never sends more than asked.
func (e Evidence) HashPaths() bool { return e.PathMode != PathModeFull }

// Decode parses and checks a bundle. It enforces the contract's caps (bundle
// JSON, rulesets, rule source sizes) and the shape of every id, hash and
// storage path, so nothing downstream acts on a malformed bundle. Limits the
// bundle leaves out or sends out of range take their safe defaults.
func Decode(raw []byte) (*Bundle, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) > MaxBundleBytes {
		return nil, fmt.Errorf("%w: bundle is %d bytes (max %d)", ErrTooLarge, len(raw), MaxBundleBytes)
	}
	var probe struct {
		SchemaVersion *int `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidBundle, err)
	}
	if probe.SchemaVersion == nil || *probe.SchemaVersion != SchemaVersion {
		v := "missing"
		if probe.SchemaVersion != nil {
			v = fmt.Sprint(*probe.SchemaVersion)
		}
		return nil, fmt.Errorf("%w: %s (this agent understands %d)", ErrUnsupportedSchema, v, SchemaVersion)
	}
	b := &Bundle{Limits: DefaultLimits()}
	if err := json.Unmarshal(raw, b); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidBundle, err)
	}
	if err := b.check(); err != nil {
		return nil, err
	}
	b.Limits = b.Limits.normalized()
	if !b.Enabled || (b.OnWrite != nil && !b.OnWrite.Enabled) {
		b.OnWrite = nil
	}
	if !b.Enabled {
		b.Rulesets, b.Schedules = nil, nil
	}
	return b, nil
}

func (b *Bundle) check() error {
	if b.Version == "" || len(b.Version) > MaxVersionLen {
		return fmt.Errorf("%w: version must be 1-%d characters", ErrInvalidBundle, MaxVersionLen)
	}
	if !b.Enabled {
		return nil // rulesets and schedules are ignored
	}
	if len(b.Rulesets) > MaxRulesets {
		return fmt.Errorf("%w: %d rulesets (max %d)", ErrTooLarge, len(b.Rulesets), MaxRulesets)
	}
	ids := make(map[string]bool, len(b.Rulesets))
	var total int64
	for i, r := range b.Rulesets {
		if err := r.check(); err != nil {
			return fmt.Errorf("ruleset %d: %w", i, err)
		}
		key := strings.ToLower(r.ID)
		if ids[key] {
			return fmt.Errorf("%w: ruleset %s listed twice", ErrInvalidBundle, r.ID)
		}
		ids[key] = true
		total += r.Size
	}
	if total > MaxBundleRuleBytes {
		return fmt.Errorf("%w: rule sources total %d bytes (max %d)", ErrTooLarge, total, MaxBundleRuleBytes)
	}
	for i, s := range b.Schedules {
		if err := s.check(ids); err != nil {
			return fmt.Errorf("schedule %d: %w", i, err)
		}
	}
	if b.OnWrite != nil && b.OnWrite.Enabled {
		if err := b.OnWrite.check(ids); err != nil {
			return fmt.Errorf("on_write: %w", err)
		}
	}
	return nil
}

func (o *OnWrite) check(rulesets map[string]bool) error {
	for _, l := range []OSPaths{o.Paths, o.Exclusions} {
		for _, list := range [][]string{l.Windows, l.Darwin, l.Linux} {
			if len(list) > MaxOnWritePaths {
				return fmt.Errorf("%w: %d paths for one OS (max %d)", ErrInvalidBundle, len(list), MaxOnWritePaths)
			}
			for _, p := range list {
				if p == "" || len(p) > MaxPathLen || strings.ContainsRune(p, 0) {
					return fmt.Errorf("%w: paths must be 1-%d characters", ErrInvalidBundle, MaxPathLen)
				}
			}
		}
	}
	for _, id := range o.RulesetIDs {
		if !rulesets[strings.ToLower(id)] {
			return fmt.Errorf("%w: ruleset %q isn't in the bundle", ErrInvalidBundle, id)
		}
	}
	return nil
}

func (r Ruleset) check() error {
	switch {
	case !IsUUID(r.ID):
		return fmt.Errorf("%w: id %q is not a UUID", ErrInvalidBundle, r.ID)
	case r.Revision < 0:
		return fmt.Errorf("%w: negative revision", ErrInvalidBundle)
	case !IsSHA256(r.SHA256):
		return fmt.Errorf("%w: sha256 is not a hex SHA-256", ErrInvalidBundle)
	case r.Size < 0:
		return fmt.Errorf("%w: negative size", ErrInvalidBundle)
	case r.Size > MaxRulesetBytes:
		return fmt.Errorf("%w: rule source is %d bytes (max %d)", ErrTooLarge, r.Size, MaxRulesetBytes)
	case !validStoragePath(r.StoragePath):
		return fmt.Errorf("%w: storage_path %q", ErrInvalidBundle, r.StoragePath)
	}
	return nil
}

// validStoragePath accepts a relative object path inside the yara/ prefix,
// with no empty, "." or ".." segment and no backslash, so it can only name
// an object the bundle meant.
func validStoragePath(p string) bool {
	if !strings.HasPrefix(p, "yara/") || len(p) > 1024 || strings.ContainsAny(p, "\\\x00?#") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return path.Clean(p) == p
}

func (s Schedule) check(rulesets map[string]bool) error {
	switch {
	case !IsUUID(s.ID):
		return fmt.Errorf("%w: id %q is not a UUID", ErrInvalidBundle, s.ID)
	case !ValidPreset(s.Preset):
		return fmt.Errorf("%w: unknown preset %q", ErrInvalidBundle, s.Preset)
	case s.EveryHours <= 0:
		return fmt.Errorf("%w: every_hours must be positive", ErrInvalidBundle)
	case s.JitterMinutes < 0:
		return fmt.Errorf("%w: negative jitter_minutes", ErrInvalidBundle)
	}
	for _, id := range s.RulesetIDs {
		if !rulesets[strings.ToLower(id)] {
			return fmt.Errorf("%w: ruleset %q isn't in the bundle", ErrInvalidBundle, id)
		}
	}
	return nil
}

// normalized replaces limits that are missing or out of range with the safe
// defaults; a CPU budget is at most one core.
func (l Limits) normalized() Limits {
	d := DefaultLimits()
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.PerFileTimeoutMS <= 0 {
		l.PerFileTimeoutMS = d.PerFileTimeoutMS
	}
	if l.MaxCPUPercent <= 0 || l.MaxCPUPercent > 100 {
		l.MaxCPUPercent = d.MaxCPUPercent
	}
	if l.MaxFilesPerScan <= 0 {
		l.MaxFilesPerScan = d.MaxFilesPerScan
	}
	if l.MaxScanMinutes <= 0 {
		l.MaxScanMinutes = d.MaxScanMinutes
	}
	return l
}

// RulesetsFor returns the bundle's rulesets with the given ids, all of them
// when ids is nil. Unknown ids are left out.
func (b *Bundle) RulesetsFor(ids []string) []Ruleset {
	if ids == nil {
		return b.Rulesets
	}
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[strings.ToLower(id)] = true
	}
	var out []Ruleset
	for _, r := range b.Rulesets {
		if want[strings.ToLower(r.ID)] {
			out = append(out, r)
		}
	}
	return out
}
