package telemetry

import (
	"sort"
	"time"
)

// Domain health states, as surfaced to operators.
const (
	// HealthHealthy: last collection succeeded.
	HealthHealthy = "healthy"
	// HealthPartial: data was produced but incomplete.
	HealthPartial = "partial"
	// HealthDisabled: switched off by configuration.
	HealthDisabled = "disabled"
	// HealthNotApplicable: the hardware or feature does not exist here. This is
	// a steady state, not a problem to chase.
	HealthNotApplicable = "not_applicable"
	// HealthPermissionDenied: the agent lacks rights to read the data.
	HealthPermissionDenied = "permission_denied"
	// HealthFailing: collection is erroring or timing out.
	HealthFailing = "failing"
)

// DomainHealth is the collection health of a single telemetry domain.
type DomainHealth struct {
	Domain                string `json:"domain"`
	State                 string `json:"state"`
	LastSuccessfulCollect string `json:"last_successful_collection,omitempty"`
	LastUpload            string `json:"last_upload,omitempty"`
	ConsecutiveFailures   int    `json:"consecutive_failures"`
	// LastError is a sanitized reason code, never raw output.
	LastError string `json:"last_error,omitempty"`
}

// TelemetryHealth summarises the agent's own collection and delivery health so
// the platform can distinguish "this endpoint reports no certificates" from
// "this endpoint's certificate collector has been failing for a week".
type TelemetryHealth struct {
	Domains           []DomainHealth `json:"domains"`
	PendingQueueDepth int            `json:"pending_queue_depth"`
	DroppedEventCount int64          `json:"dropped_event_count"`
	CollectorFailures int64          `json:"collector_failures"`
	LastFullSnapshot  string         `json:"last_full_snapshot,omitempty"`
}

// HealthStateFor maps a collection status and capability state to a domain
// health state.
//
// Capability is consulted first: a desktop with no battery must report
// not_applicable indefinitely rather than accumulating failures for hardware it
// will never have.
func HealthStateFor(status Status, cap CapabilityState) string {
	switch cap {
	case CapDisabled:
		return HealthDisabled
	case CapNotPresent, CapUnavailableOS, CapNotCollected:
		// CapNotCollected joins these because a key nobody claimed has no
		// collector to be unhealthy: counting it as a failure would make every
		// build report itself as failing for the capabilities it does not ship.
		return HealthNotApplicable
	}

	switch status {
	case StatusSuccess:
		return HealthHealthy
	case StatusPartial:
		return HealthPartial
	case StatusUnsupported:
		return HealthNotApplicable
	case StatusPermissionDenied:
		return HealthPermissionDenied
	case StatusTimeout, StatusError:
		return HealthFailing
	default:
		return HealthFailing
	}
}

// HealthTracker accumulates collector outcomes into a TelemetryHealth report.
// It is not safe for concurrent use; the telemetry task runs collectors
// sequentially within one cycle.
type HealthTracker struct {
	domains           map[string]*DomainHealth
	collectorFailures int64
	droppedEvents     int64
	pendingDepth      int
	lastFullSnapshot  time.Time
}

// NewHealthTracker returns an empty tracker.
func NewHealthTracker() *HealthTracker {
	return &HealthTracker{domains: make(map[string]*DomainHealth)}
}

// Observe folds one collector result into the tracker.
func (t *HealthTracker) Observe(res CollectorResult, cap CapabilityState) {
	d, ok := t.domains[res.Section]
	if !ok {
		d = &DomainHealth{Domain: res.Section}
		t.domains[res.Section] = d
	}

	d.State = HealthStateFor(res.Status, cap)

	if res.Status.OK() {
		d.LastSuccessfulCollect = res.CollectedAt
		d.ConsecutiveFailures = 0
		d.LastError = ""
		return
	}

	// Only genuine faults count as failures. Unsupported and not-present data
	// would otherwise inflate the failure count forever on hardware that simply
	// lacks the feature.
	if res.Status.Failed() {
		d.ConsecutiveFailures++
		t.collectorFailures++
		d.LastError = res.Error
	}
}

// MarkUploaded records a successful upload time for a domain.
func (t *HealthTracker) MarkUploaded(section string, at time.Time) {
	d, ok := t.domains[section]
	if !ok {
		d = &DomainHealth{Domain: section, State: HealthHealthy}
		t.domains[section] = d
	}
	d.LastUpload = at.UTC().Format(time.RFC3339)
}

// SetQueueDepth records the current outbound queue depth.
func (t *HealthTracker) SetQueueDepth(n int) { t.pendingDepth = n }

// AddDropped adds to the count of telemetry dropped by queue eviction, so loss
// is always visible rather than silent.
func (t *HealthTracker) AddDropped(n int64) { t.droppedEvents += n }

// SetLastFullSnapshot records when the agent last sent a complete snapshot.
func (t *HealthTracker) SetLastFullSnapshot(at time.Time) { t.lastFullSnapshot = at }

// Report renders the accumulated state, with domains sorted for stable output.
func (t *HealthTracker) Report() *TelemetryHealth {
	names := make([]string, 0, len(t.domains))
	for name := range t.domains {
		names = append(names, name)
	}
	sort.Strings(names)

	domains := make([]DomainHealth, 0, len(names))
	for _, name := range names {
		domains = append(domains, *t.domains[name])
	}

	h := &TelemetryHealth{
		Domains:           domains,
		PendingQueueDepth: t.pendingDepth,
		DroppedEventCount: t.droppedEvents,
		CollectorFailures: t.collectorFailures,
	}
	if !t.lastFullSnapshot.IsZero() {
		h.LastFullSnapshot = t.lastFullSnapshot.UTC().Format(time.RFC3339)
	}
	return h
}
