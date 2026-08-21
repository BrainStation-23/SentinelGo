// Package persistence implements the telemetry Persistence collector,
// filling the "persistence" section: mechanisms that make something run
// automatically — registry run keys and scheduled tasks on Windows, systemd
// units and cron on Linux, launchd jobs on macOS.
//
// Scope in this pass, and what is deliberately deferred:
//   - Windows: HKLM Run/RunOnce (machine-wide) and scheduled tasks are
//     covered. Per-user HKCU run keys are not: reading them correctly for
//     every logged-in user from a SYSTEM service needs the HKEY_USERS-per-SID
//     enumeration docs/telemetry/03-collection-matrix.md points to (already
//     proven in internal/service/software/collect_windows.go) — real,
//     separable work, not folded into this pass. Startup folders are
//     likewise deferred.
//   - Linux: systemd units and crontab-family entries are covered. XDG
//     autostart is not.
//   - macOS: LaunchDaemons/LaunchAgents are covered, filtered to exclude
//     Apple's own several-hundred-entry set the same way the matrix doc
//     recommends for launchd generally.
//
// Payload is a bare slice, not a struct wrapping one: SectionPersistence is
// registered Chunked in section.go, and telemetry.ChunkSection requires the
// value Collect returns to reflect as a slice directly (see chunk.go and the
// patches collector, which established this pattern first).
package persistence

import (
	"context"
	"sort"

	tel "sentinelgo/internal/telemetry"
)

// Name is the collector's identifier, also used as its section name.
const Name = tel.SectionPersistence

// Entry describes one auto-run mechanism.
type Entry struct {
	// Type is "registry_run_key", "scheduled_task", "systemd_service",
	// "cron", or "launchd".
	Type    string `json:"type"`
	Name    string `json:"name,omitempty"`
	Command string `json:"command,omitempty"`
	// Location is the registry key, unit file path, crontab path, or plist
	// path this entry came from.
	Location string `json:"location,omitempty"`
	// Enabled is *bool: nil means this platform's mechanism did not report
	// an enabled/disabled state for this entry (registry run keys have no
	// such concept — their mere presence is the signal), never a guessed
	// true/false.
	Enabled *bool `json:"enabled,omitempty"`
}

// Payload is the wire shape of the "persistence" section — see the package
// doc for why this is a bare slice rather than a struct.
type Payload []Entry

// signal is what platform code supplies before assembling Payload.
type signal struct {
	Entries  []Entry
	Err      error
	Source   string
	Warnings []string
}

// Collector implements telemetry.Collector for persistence inventory.
type Collector struct{}

// New returns the Persistence collector.
func New() *Collector { return &Collector{} }

func (c *Collector) Name() string       { return Name }
func (c *Collector) Section() string    { return tel.SectionPersistence }
func (c *Collector) SchemaVersion() int { return 1 }

// Capability reports persistence inventory as always supported: every
// platform has at least one of the mechanisms this collector reads.
func (c *Collector) Capability(context.Context, tel.CollectorConfig) (string, tel.CapabilityState) {
	return tel.CapKeyPersistence, tel.CapSupported
}

// Collect gathers persistence mechanism inventory.
func (c *Collector) Collect(ctx context.Context, cfg tel.CollectorConfig) (any, tel.CollectorResult) {
	res, done := tel.NewResult(c.Name(), c.Section())

	sig := platformEntries(ctx, cfg)
	for _, w := range sig.Warnings {
		res.AddWarning(w)
	}

	sortEntries(sig.Entries)
	entries := sig.Entries
	if cfg.MaxItems > 0 && len(entries) > cfg.MaxItems {
		entries = entries[:cfg.MaxItems]
	}

	return Payload(entries), *done(sig.Err, sig.Source, len(entries))
}

// sortEntries orders the list deterministically by type then name, so an
// unchanged entry set hashes identically cycle to cycle — Fingerprint's
// documented requirement for any list payload.
func sortEntries(e []Entry) {
	sort.Slice(e, func(i, j int) bool {
		if e[i].Type != e[j].Type {
			return e[i].Type < e[j].Type
		}
		return e[i].Name < e[j].Name
	})
}
