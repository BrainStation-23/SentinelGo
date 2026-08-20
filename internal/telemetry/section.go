package telemetry

import (
	"sort"
	"time"
)

// Section names. Part of the backend contract: add, never rename.
const (
	SectionIdentity       = "identity"
	SectionVirtualization = "virtualization"
	SectionDirectory      = "directory"
	SectionFirmware       = "firmware"
	SectionTPM            = "tpm"
	SectionCPU            = "cpu"
	SectionMemoryModules  = "memory_modules"
	SectionPhysicalDisks  = "physical_disks"
	SectionOS             = "os"
	SectionVolumes        = "volumes"
	SectionNetwork        = "network"
	SectionSessions       = "sessions"
	SectionSecurityPost   = "security_posture"
	SectionEncryption     = "encryption"
	SectionSecureBoot     = "secure_boot"
	SectionPatches        = "patches"
	SectionPersistence    = "persistence"
	SectionProcesses      = "processes"
	SectionCertificates   = "certificates"
	SectionHealth         = "health"
)

// SectionSpec describes how one telemetry section is collected and reconciled.
//
// CollectInterval and ReconcileInterval are deliberately separate. Collection
// is what costs the endpoint; upload is what costs the backend. A stable
// device should keep checking its hardware every few hours but only re-send
// that unchanged data once a day.
type SectionSpec struct {
	Name              string
	Class             Class
	SchemaVersion     int
	CollectInterval   time.Duration
	ReconcileInterval time.Duration
	// Chunked marks a high-cardinality section whose payload must be split into
	// batches rather than truncated. See chunk.go.
	Chunked bool
}

// Fingerprinted reports whether this section participates in change detection.
func (s SectionSpec) Fingerprinted() bool { return s.Class.Fingerprinted() }

// DefaultSections is the registry of sections this agent knows how to produce.
//
// Note that "software" and "services" are absent on purpose: they remain on the
// existing legacy pipeline at its current cadence. Moving them is a change to a
// working subsystem and is tracked separately.
func DefaultSections() []SectionSpec {
	const h = time.Hour
	const m = time.Minute
	return []SectionSpec{
		// Static hardware and identity: cheap to re-read, almost never changes.
		{SectionIdentity, ClassInventory, 1, 6 * h, 24 * h, false},
		{SectionVirtualization, ClassInventory, 1, 6 * h, 24 * h, false},
		{SectionFirmware, ClassInventory, 1, 6 * h, 24 * h, false},
		{SectionTPM, ClassInventory, 1, 6 * h, 24 * h, false},
		{SectionCPU, ClassInventory, 1, 6 * h, 24 * h, false},
		{SectionMemoryModules, ClassInventory, 1, 6 * h, 24 * h, false},
		{SectionPhysicalDisks, ClassInventory, 1, 6 * h, 24 * h, false},

		// Dynamic inventory.
		{SectionOS, ClassInventory, 1, 1 * h, 24 * h, false},
		{SectionVolumes, ClassInventory, 1, 1 * h, 24 * h, false},
		{SectionNetwork, ClassInventory, 1, 1 * h, 24 * h, false},
		// Directory join can change independently of a reboot (a device can be
		// joined or unjoined at any time), so it collects on the same cadence as
		// other dynamic inventory rather than the 6h static-hardware bucket.
		{SectionDirectory, ClassInventory, 1, 1 * h, 24 * h, false},
		{SectionSessions, ClassInventory, 1, 15 * m, 4 * h, false},
		{SectionPersistence, ClassInventory, 1, 1 * h, 12 * h, true},
		{SectionProcesses, ClassInventory, 1, 15 * m, 1 * h, true},
		{SectionCertificates, ClassInventory, 1, 12 * h, 24 * h, true},

		// Security posture: collected often, reconciled hourly.
		{SectionSecurityPost, ClassPosture, 1, 15 * m, 1 * h, false},
		{SectionEncryption, ClassPosture, 1, 15 * m, 1 * h, false},
		{SectionSecureBoot, ClassPosture, 1, 15 * m, 1 * h, false},
		{SectionPatches, ClassPosture, 1, 6 * h, 12 * h, true},

		// Health is sampled, never fingerprinted or reconciled.
		{SectionHealth, ClassHealth, 1, 15 * m, 0, false},
	}
}

// Registry indexes section specs by name.
type Registry struct {
	specs map[string]SectionSpec
	order []string
}

// NewRegistry builds a registry from specs. Later entries with the same name
// replace earlier ones, so a caller can override a default.
func NewRegistry(specs []SectionSpec) *Registry {
	r := &Registry{specs: make(map[string]SectionSpec, len(specs))}
	for _, s := range specs {
		if _, exists := r.specs[s.Name]; !exists {
			r.order = append(r.order, s.Name)
		}
		r.specs[s.Name] = s
	}
	sort.Strings(r.order)
	return r
}

// NewDefaultRegistry returns a registry of the built-in sections.
func NewDefaultRegistry() *Registry { return NewRegistry(DefaultSections()) }

// Get returns the spec for name.
func (r *Registry) Get(name string) (SectionSpec, bool) {
	s, ok := r.specs[name]
	return s, ok
}

// Names returns the registered section names in sorted order.
func (r *Registry) Names() []string {
	out := make([]string, len(r.order))
	copy(out, r.order)
	return out
}

// SectionVersions maps each registered section to its schema version, for the
// envelope's section_versions field.
func (r *Registry) SectionVersions() map[string]int {
	out := make(map[string]int, len(r.specs))
	for name, spec := range r.specs {
		out[name] = spec.SchemaVersion
	}
	return out
}

// SectionState is the persisted reconciliation state for one section. It holds
// hashes and timestamps only — never the payload itself.
type SectionState struct {
	Section          string
	SchemaVersion    int
	Hash             string
	ItemCount        int
	Status           string
	LastCollectedAt  time.Time
	LastUploadedAt   time.Time
	LastReconciledAt time.Time
}

// UploadDecision explains whether a section should be uploaded, and why.
type UploadDecision struct {
	Upload bool
	Reason string
}

// Upload reasons.
const (
	ReasonChanged       = "changed"
	ReasonReconcileDue  = "reconcile_due"
	ReasonFirstUpload   = "first_upload"
	ReasonSchemaChanged = "schema_changed"
	ReasonUnchanged     = "unchanged"
	ReasonHealthSample  = "health_sample"
)

// ShouldUpload decides whether a freshly collected section needs to be sent.
//
// A section uploads when its content hash changed, when its schema version
// changed (the backend must see the new shape), when it has never been
// uploaded, or when its reconcile interval has elapsed. Health sections always
// upload: they are samples, and suppressing an unchanged sample would misreport
// the device as idle rather than steady.
func ShouldUpload(spec SectionSpec, prev *SectionState, newHash string, now time.Time) UploadDecision {
	if spec.Class == ClassHealth {
		return UploadDecision{Upload: true, Reason: ReasonHealthSample}
	}
	if prev == nil || prev.Hash == "" || prev.LastUploadedAt.IsZero() {
		return UploadDecision{Upload: true, Reason: ReasonFirstUpload}
	}
	if prev.SchemaVersion != spec.SchemaVersion {
		return UploadDecision{Upload: true, Reason: ReasonSchemaChanged}
	}
	if prev.Hash != newHash {
		return UploadDecision{Upload: true, Reason: ReasonChanged}
	}
	if spec.ReconcileInterval > 0 && now.Sub(prev.LastReconciledAt) >= spec.ReconcileInterval {
		return UploadDecision{Upload: true, Reason: ReasonReconcileDue}
	}
	return UploadDecision{Upload: false, Reason: ReasonUnchanged}
}

// DueForCollection reports whether a section's collect interval has elapsed.
func DueForCollection(spec SectionSpec, prev *SectionState, now time.Time) bool {
	if prev == nil || prev.LastCollectedAt.IsZero() {
		return true
	}
	if spec.CollectInterval <= 0 {
		return true
	}
	return now.Sub(prev.LastCollectedAt) >= spec.CollectInterval
}
