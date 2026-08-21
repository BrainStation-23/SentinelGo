// Package patches implements the telemetry Patch Inventory collector,
// filling the "patches" section with installed and pending OS updates.
//
// Win32_QuickFixEngineering alone (the legacy pipeline's mechanism) is not
// sufficient per docs/telemetry/03-collection-matrix.md: it covers quality
// updates only and misses feature updates, driver updates and Store updates
// entirely, and it carries no pending/history distinction. This collector
// adds the pending side of the picture; see each platform file's doc comment
// for the installed-side mechanism it uses.
//
// Payload is a bare slice, not a struct wrapping one: SectionPatches is
// registered Chunked in section.go, and telemetry.ChunkSection requires the
// value Collect returns to reflect as a slice directly (see chunk.go) so it
// can split a large update list across multiple queued messages.
package patches

import (
	"context"
	"sort"

	tel "sentinelgo/internal/telemetry"
)

// Name is the collector's identifier, also used as its section name.
const Name = tel.SectionPatches

// Update describes one installed or pending OS update.
type Update struct {
	// ID is a KB number, package name, or other platform identifier.
	ID          string `json:"id,omitempty"`
	Description string `json:"description,omitempty"`
	// Category is "quality", "feature", "driver", "package", or "unknown"
	// when the platform does not distinguish.
	Category string `json:"category,omitempty"`
	// Status is "installed" or "pending".
	Status string `json:"status"`
	// InstalledOn is RFC3339, installed items only.
	InstalledOn string `json:"installed_on,omitempty"`
}

// Payload is the wire shape of the "patches" section — see the package doc
// for why this is a bare slice rather than a struct.
type Payload []Update

// signal is what platform code supplies before assembling Payload.
type signal struct {
	Updates  []Update
	Err      error
	Source   string
	Warnings []string
}

// Collector implements telemetry.Collector for patch inventory.
type Collector struct{}

// New returns the Patch Inventory collector.
func New() *Collector { return &Collector{} }

func (c *Collector) Name() string       { return Name }
func (c *Collector) Section() string    { return tel.SectionPatches }
func (c *Collector) SchemaVersion() int { return 1 }

// Capability reports patch inventory as always supported: every platform
// ships a package/update manager (WMI+WU on Windows, dpkg/rpm on Linux,
// softwareupdate on macOS).
func (c *Collector) Capability(context.Context, tel.CollectorConfig) (string, tel.CapabilityState) {
	return tel.CapKeyPatchInventory, tel.CapSupported
}

// Collect gathers installed and pending update inventory.
func (c *Collector) Collect(ctx context.Context, _ tel.CollectorConfig) (any, tel.CollectorResult) {
	res, done := tel.NewResult(c.Name(), c.Section())

	sig := platformUpdates(ctx)
	for _, w := range sig.Warnings {
		res.AddWarning(w)
	}

	sortUpdates(sig.Updates)

	return Payload(sig.Updates), *done(sig.Err, sig.Source, len(sig.Updates))
}

// sortUpdates orders the list deterministically (status, then ID), so an
// unchanged update set hashes identically cycle to cycle — Fingerprint's
// documented requirement for any list payload.
func sortUpdates(u []Update) {
	sort.Slice(u, func(i, j int) bool {
		if u[i].Status != u[j].Status {
			return u[i].Status < u[j].Status
		}
		return u[i].ID < u[j].ID
	})
}
