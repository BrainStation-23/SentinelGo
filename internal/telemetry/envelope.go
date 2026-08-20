package telemetry

import (
	"runtime"
	"sort"
	"time"

	"sentinelgo/internal/config"
)

// EnvelopeSchemaVersion is the version of the envelope itself. Section payloads
// carry their own versions in SectionVersions, so an individual domain can
// evolve without forcing a global bump.
const EnvelopeSchemaVersion = 1

// Meta carries per-cycle diagnostics about the collection run.
//
// Meta lives on the envelope and NEVER inside a section payload. Its fields
// (durations, timestamps, queue depths, counters) change on every cycle; a
// section containing them would hash differently every time and mark itself
// permanently changed, silently disabling reconciliation. Fingerprint enforces
// this at runtime — see guardNotMeta.
type Meta struct {
	Results []CollectorResult `json:"results,omitempty"`
	Health  *TelemetryHealth  `json:"telemetry_health,omitempty"`
}

// Envelope is the wire format for the telemetry layer's own RPC. It is never
// applied to the legacy inventory payload, which keeps its existing shape.
type Envelope struct {
	SchemaVersion int    `json:"schema_version"`
	AgentVersion  string `json:"agent_version"`
	DeviceID      string `json:"device_id"`
	CollectedAt   string `json:"collected_at"`
	Platform      string `json:"platform"`
	Class         Class  `json:"class"`

	// CollectionGeneration is a device-persisted monotonic counter allocated
	// once per collection cycle. Every envelope and chunk produced by that
	// cycle carries the same value. The backend uses it before endpoint wall
	// clock time, so a delayed retry can never replace a later collection.
	CollectionGeneration uint64 `json:"collection_generation,omitempty"`

	// FullSnapshot marks a message carrying every section the agent produces,
	// as opposed to the changed subset. Set on first upload after provisioning
	// and on a periodic full reconcile.
	FullSnapshot bool `json:"full_snapshot"`

	// Sections lists the sections carried in Data AND asserts that they are
	// authoritative in this message.
	//
	// This field is a correctness requirement, not metadata. Once sections
	// upload independently, most messages carry only what changed — so the
	// backend MUST merge the listed sections and leave the rest untouched.
	// A backend that replaces wholesale would wipe every section that simply
	// had nothing new to report.
	Sections []string `json:"sections"`

	// SectionVersions gives the schema version of each carried section.
	SectionVersions map[string]int `json:"section_versions,omitempty"`

	Capabilities CapabilityManifest `json:"capabilities,omitempty"`

	// Data holds the section payloads, keyed by section name.
	Data SectionData `json:"data,omitempty"`

	// Chunk is set only for chunked, high-cardinality sections.
	Chunk *ChunkMeta `json:"chunk,omitempty"`

	Meta *Meta `json:"meta,omitempty"`
}

// NewEnvelope builds an envelope for a class of telemetry.
func NewEnvelope(cfg *config.Config, class Class, now time.Time) *Envelope {
	deviceID, agentVersion := "", ""
	if cfg != nil {
		deviceID = cfg.DeviceID
		agentVersion = cfg.CurrentVersion
	}
	return &Envelope{
		SchemaVersion: EnvelopeSchemaVersion,
		AgentVersion:  agentVersion,
		DeviceID:      deviceID,
		CollectedAt:   now.UTC().Format(time.RFC3339),
		Platform:      runtime.GOOS,
		Class:         class,
		Data:          make(SectionData),
	}
}

// AddSection attaches a section payload and records it as authoritative.
func (e *Envelope) AddSection(name string, version int, payload any) {
	if e.Data == nil {
		e.Data = make(SectionData)
	}
	if e.SectionVersions == nil {
		e.SectionVersions = make(map[string]int)
	}
	if _, exists := e.Data[name]; !exists {
		e.Sections = append(e.Sections, name)
	}
	e.Data[name] = payload
	e.SectionVersions[name] = version
}

// Finalize sorts the section list for stable output and sanitizes every
// CollectorResult so no unbounded or unredacted string can reach the wire.
//
// Call this immediately before marshalling. It is idempotent.
func (e *Envelope) Finalize() {
	sort.Strings(e.Sections)
	if e.Meta == nil {
		return
	}
	for i := range e.Meta.Results {
		e.Meta.Results[i].Sanitize()
	}
	if e.Meta.Health != nil {
		for i := range e.Meta.Health.Domains {
			d := &e.Meta.Health.Domains[i]
			d.LastError = SanitizeMessage(d.LastError)
		}
	}
}

// IsEmpty reports whether the envelope carries no section data. An empty
// envelope should not be enqueued.
func (e *Envelope) IsEmpty() bool { return len(e.Data) == 0 }
