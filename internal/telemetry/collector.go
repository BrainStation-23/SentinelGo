package telemetry

import (
	"context"
	"fmt"
	"sort"
)

// Collector produces the payload for exactly one telemetry section.
//
// Every collector takes a context from the outset. The legacy inventory path
// cannot be cancelled — its 90-second timeout abandons the goroutine while the
// subprocesses it spawned keep running — and that debt must not grow. New
// collectors honour cancellation so a slow WMI query or a spun-down disk cannot
// outlive its cycle.
type Collector interface {
	// Name identifies the collector in logs and CollectorResult.
	Name() string
	// Section is the telemetry section this collector fills.
	Section() string
	// SchemaVersion is the payload's schema version, bumped when its shape changes.
	SchemaVersion() int
	// Capability reports which capability key this collector owns and its state
	// on this endpoint. Called even when Collect is skipped, so the backend
	// always learns why data is absent.
	Capability(ctx context.Context, cfg CollectorConfig) (key string, state CapabilityState)
	// Collect gathers the section payload. Implementations must return a result
	// describing the outcome even on failure, and must never return raw command
	// output in it — use SanitizeError.
	Collect(ctx context.Context, cfg CollectorConfig) (payload any, result CollectorResult)
}

// CollectorConfig is the subset of agent configuration collectors may read.
//
// Passing a narrow struct rather than *config.Config keeps the telemetry layer
// decoupled from the global config type and makes collectors trivially testable.
type CollectorConfig struct {
	// CollectProcessCmdline enables process command-line capture. Off by
	// default: command lines routinely carry tokens, passwords and connection
	// strings passed as arguments.
	CollectProcessCmdline bool
	// IncludeBuiltinScheduledTasks includes OS-shipped scheduled tasks on
	// Windows. Off by default; they are ~90% of the list and rarely of interest.
	IncludeBuiltinScheduledTasks bool
	// CollectRoutingTable enables full routing-table collection, which is
	// detailed telemetry rather than basic inventory.
	CollectRoutingTable bool
	// MaxItems caps high-cardinality lists. Zero means unlimited.
	MaxItems int
}

// CollectorSet is an ordered, name-unique group of collectors.
type CollectorSet struct {
	collectors map[string]Collector
	order      []string
}

// NewCollectorSet returns an empty set.
func NewCollectorSet() *CollectorSet {
	return &CollectorSet{collectors: make(map[string]Collector)}
}

// Register adds c. Registering a duplicate name is an error rather than a
// silent overwrite, so a copy-paste mistake surfaces at startup.
func (s *CollectorSet) Register(c Collector) error {
	if c == nil {
		return fmt.Errorf("telemetry: nil collector")
	}
	name := c.Name()
	if name == "" {
		return fmt.Errorf("telemetry: collector with empty name")
	}
	if _, exists := s.collectors[name]; exists {
		return fmt.Errorf("telemetry: collector %q already registered", name)
	}
	s.collectors[name] = c
	s.order = append(s.order, name)
	sort.Strings(s.order)
	return nil
}

// Get returns the collector registered under name.
func (s *CollectorSet) Get(name string) (Collector, bool) {
	c, ok := s.collectors[name]
	return c, ok
}

// Names returns the registered collector names in sorted order.
func (s *CollectorSet) Names() []string {
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}

// Len returns the number of registered collectors.
func (s *CollectorSet) Len() int { return len(s.collectors) }

// All returns the collectors in sorted-name order, giving a deterministic
// collection sequence across runs.
func (s *CollectorSet) All() []Collector {
	out := make([]Collector, 0, len(s.order))
	for _, name := range s.order {
		out = append(out, s.collectors[name])
	}
	return out
}

// RunAll executes every collector in order, honouring cancellation between
// each. It returns the section payloads, the per-collector results, the
// capability manifest, and each collector's capability state indexed by
// section name.
//
// The last return value exists because a section name and the capability key
// that gates it are not always equal — SectionPatches is "patches" but its key
// is CapKeyPatchInventory ("patch_inventory"), and a section like SectionCPU
// owns no capability key at all. The wire-facing CapabilityManifest must stay
// indexed by capability key (that shape is the backend contract), so callers
// that need "what was this SECTION's capability state" — health bookkeeping,
// specifically — need this separate, section-indexed view rather than
// re-deriving it by assuming the two strings match.
//
// A collector that panics is contained: the surrounding cycle continues and the
// failure is reported as that collector's result. One malformed WMI response
// must not cost the agent every other section in the cycle.
func RunAll(ctx context.Context, set *CollectorSet, cfg CollectorConfig) (SectionData, []CollectorResult, CapabilityManifest, map[string]CapabilityState) {
	data := make(SectionData)
	results := make([]CollectorResult, 0, set.Len())
	caps := NewCapabilityManifest()
	sectionCaps := make(map[string]CapabilityState, set.Len())

	for _, c := range set.All() {
		if ctx.Err() != nil {
			break
		}
		payload, res, capKey, capState := runOne(ctx, c, cfg)
		if capKey != "" {
			caps.Set(capKey, capState)
		}
		sectionCaps[c.Section()] = capState
		results = append(results, res)
		if payload != nil && res.Status.OK() {
			data[c.Section()] = payload
		}
	}
	return data, results, caps, sectionCaps
}

// runOne executes a single collector with panic containment.
func runOne(ctx context.Context, c Collector, cfg CollectorConfig) (payload any, res CollectorResult, capKey string, capState CapabilityState) {
	defer func() {
		if r := recover(); r != nil {
			payload = nil
			res = CollectorResult{
				Collector: c.Name(),
				Section:   c.Section(),
				Status:    StatusError,
				Error:     ReasonUnexpected,
			}
			res.Sanitize()
		}
	}()

	capKey, capState = c.Capability(ctx, cfg)

	// Skip collection when the capability says there is nothing to collect. The
	// result still reports why, so the backend never has to guess.
	if capState != CapSupported {
		res = CollectorResult{
			Collector: c.Name(),
			Section:   c.Section(),
			Status:    statusForCapability(capState),
			Error:     reasonForCapability(capState),
		}
		res.Sanitize()
		return nil, res, capKey, capState
	}

	payload, res = c.Collect(ctx, cfg)
	res.Sanitize()
	return payload, res, capKey, capState
}

func statusForCapability(state CapabilityState) Status {
	switch state {
	case CapDisabled, CapNotPresent, CapUnsupported, CapUnavailableOS:
		return StatusUnsupported
	default:
		return StatusSuccess
	}
}

func reasonForCapability(state CapabilityState) string {
	switch state {
	case CapDisabled:
		return "disabled_by_config"
	case CapNotPresent:
		return "not_present"
	case CapUnsupported:
		return ReasonNotSupported
	case CapUnavailableOS:
		return "unavailable_on_os"
	default:
		return ""
	}
}
