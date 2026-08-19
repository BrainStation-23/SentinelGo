package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/models"
	"sentinelgo/internal/sanitize"
)

// StateStore persists per-section reconciliation state.
//
// The telemetry package depends on this interface rather than the concrete
// SQLite store so the cycle logic can be tested without a database — the same
// approach the software service takes with its Catalog interface.
type StateStore interface {
	GetAll() (map[string]*SectionState, error)
	MarkCollected(section string, schemaVersion int, hash string, itemCount int, status string, at time.Time) error
	MarkUploaded(section string, at time.Time) error
}

// QueuedMessage is one envelope handed to the durable outbound queue.
type QueuedMessage struct {
	SnapshotID string
	// Sections lists every section carried, so delivery can advance exactly
	// those sections' reconcile clocks and no others.
	Sections   []string
	Class      Class
	Priority   int
	BatchIndex int
	BatchCount int
	Payload    []byte
}

// OutboundQueue is the durable, bounded send queue.
type OutboundQueue interface {
	Enqueue(msg QueuedMessage) (evicted int64, err error)
	Depth() (int, error)
}

// CycleReport summarises one telemetry cycle for logging and the CLI.
type CycleReport struct {
	CollectedSections []string
	UploadedSections  []string
	SkippedSections   []string
	Reasons           map[string]string
	Messages          int
	Evicted           int64
	Results           []CollectorResult
	Capabilities      CapabilityManifest
	Health            *TelemetryHealth
}

// Service runs telemetry collection cycles.
type Service struct {
	registry *Registry
	set      *CollectorSet
	state    StateStore
	queue    OutboundQueue
	health   *HealthTracker

	// now is injectable so reconciliation intervals can be tested against a
	// frozen clock rather than by sleeping.
	now func() time.Time
}

// NewService wires a telemetry service.
func NewService(registry *Registry, set *CollectorSet, state StateStore, queue OutboundQueue) *Service {
	if registry == nil {
		registry = NewDefaultRegistry()
	}
	if set == nil {
		set = NewCollectorSet()
	}
	return &Service{
		registry: registry,
		set:      set,
		state:    state,
		queue:    queue,
		health:   NewHealthTracker(),
		now:      time.Now,
	}
}

// SetClock overrides the time source. Intended for tests.
func (s *Service) SetClock(fn func() time.Time) {
	if fn != nil {
		s.now = fn
	}
}

// Registry exposes the section registry.
func (s *Service) Registry() *Registry { return s.registry }

// Collectors exposes the registered collector set.
func (s *Service) Collectors() *CollectorSet { return s.set }

// CollectorConfigFrom projects agent config onto the narrow view collectors see.
func CollectorConfigFrom(cfg *config.Config) CollectorConfig {
	if cfg == nil {
		return CollectorConfig{}
	}
	return CollectorConfig{
		CollectProcessCmdline:        cfg.ProcessesCollectCmdline,
		IncludeBuiltinScheduledTasks: cfg.IncludeBuiltinScheduledTasks,
		CollectRoutingTable:          cfg.CollectRoutingTable,
	}
}

// RunCycle collects every registered section, decides which have changed or are
// due for reconciliation, and enqueues only those.
//
// Collection and upload are deliberately decoupled: the endpoint pays for
// collection on its own schedule, and the backend only pays for data that
// actually moved.
func (s *Service) RunCycle(ctx context.Context, cfg *config.Config) (*CycleReport, error) {
	now := s.now().UTC()

	data, results, caps := RunAll(ctx, s.set, CollectorConfigFrom(cfg))

	report := &CycleReport{
		Reasons:      make(map[string]string),
		Results:      results,
		Capabilities: caps,
	}

	for _, res := range results {
		s.health.Observe(res, caps.Get(res.Section))
	}

	if len(data) == 0 {
		report.Health = s.finishHealth()
		return report, nil
	}

	hashes, err := Fingerprint(data)
	if err != nil {
		// A metadata-in-section bug must be loud: silently continuing would
		// restore full-payload-every-cycle uploads across the fleet.
		return report, fmt.Errorf("telemetry: fingerprint failed: %w", err)
	}

	prev, err := s.loadState()
	if err != nil {
		return report, err
	}

	upload, err := s.decide(data, hashes, prev, now, report)
	if err != nil {
		return report, err
	}

	if len(upload) > 0 {
		if err := s.enqueue(cfg, upload, data, now, report); err != nil {
			return report, err
		}
	}

	report.Health = s.finishHealth()
	return report, nil
}

// loadState reads persisted section state, tolerating a missing store.
func (s *Service) loadState() (map[string]*SectionState, error) {
	if s.state == nil {
		return map[string]*SectionState{}, nil
	}
	prev, err := s.state.GetAll()
	if err != nil {
		return nil, fmt.Errorf("telemetry: read section state: %w", err)
	}
	if prev == nil {
		prev = map[string]*SectionState{}
	}
	return prev, nil
}

// decide records every collected section and returns those needing upload.
func (s *Service) decide(
	data SectionData,
	hashes SectionHashes,
	prev map[string]*SectionState,
	now time.Time,
	report *CycleReport,
) ([]string, error) {
	var upload []string

	for _, name := range sortedKeys(data) {
		spec, ok := s.registry.Get(name)
		if !ok {
			// An unregistered section has no reconcile policy, so uploading it
			// would be unbounded. Skip and say so rather than guess.
			log.Printf("[telemetry] section %s is not registered; skipping",
				sanitize.ForLog(name))
			continue
		}

		report.CollectedSections = append(report.CollectedSections, name)

		if s.state != nil {
			if err := s.state.MarkCollected(name, spec.SchemaVersion, hashes[name],
				itemCount(data[name]), string(StatusSuccess), now); err != nil {
				return nil, fmt.Errorf("telemetry: record collection for %q: %w", name, err)
			}
		}

		decision := ShouldUpload(spec, prev[name], hashes[name], now)
		report.Reasons[name] = decision.Reason
		if decision.Upload {
			upload = append(upload, name)
		} else {
			report.SkippedSections = append(report.SkippedSections, name)
		}
	}
	return upload, nil
}

// enqueue builds envelopes for the sections due for upload and queues them.
//
// Chunked sections get their own envelope so a large list can be split without
// dragging unrelated sections into every batch.
func (s *Service) enqueue(
	cfg *config.Config,
	upload []string,
	data SectionData,
	now time.Time,
	report *CycleReport,
) error {
	if s.queue == nil {
		report.UploadedSections = append(report.UploadedSections, upload...)
		return nil
	}

	grouped := make(map[Class][]string)
	var chunked []string
	for _, name := range upload {
		spec, _ := s.registry.Get(name)
		if spec.Chunked {
			chunked = append(chunked, name)
			continue
		}
		grouped[spec.Class] = append(grouped[spec.Class], name)
	}

	for _, class := range []Class{ClassInventory, ClassPosture, ClassHealth} {
		names := grouped[class]
		if len(names) == 0 {
			continue
		}
		if err := s.enqueueEnvelope(cfg, class, names, data, now, report); err != nil {
			return err
		}
	}

	for _, name := range chunked {
		spec, _ := s.registry.Get(name)
		if err := s.enqueueEnvelope(cfg, spec.Class, []string{name}, data, now, report); err != nil {
			return err
		}
	}
	return nil
}

// enqueueEnvelope builds and queues one envelope for the given sections.
func (s *Service) enqueueEnvelope(
	cfg *config.Config,
	class Class,
	names []string,
	data SectionData,
	now time.Time,
	report *CycleReport,
) error {
	env := NewEnvelope(cfg, class, now)
	env.Capabilities = report.Capabilities.Clone()
	env.Meta = &Meta{Results: report.Results, Health: s.health.Report()}

	for _, name := range names {
		spec, _ := s.registry.Get(name)
		env.AddSection(name, spec.SchemaVersion, data[name])
	}
	env.Finalize()

	body, err := json.Marshal(map[string]any{"payload": env})
	if err != nil {
		return fmt.Errorf("telemetry: marshal envelope: %w", err)
	}
	// Postgres rejects NUL bytes in text/jsonb; strip any that survived collection.
	body = sanitize.StripJSONNUL(body)

	evicted, err := s.queue.Enqueue(QueuedMessage{
		SnapshotID: NewSnapshotID(),
		Sections:   names,
		Class:      class,
		Priority:   int(models.PriorityNormal),
		BatchIndex: 0,
		BatchCount: 1,
		Payload:    body,
	})
	if err != nil {
		return fmt.Errorf("telemetry: enqueue %s envelope: %w", class, err)
	}

	report.Messages++
	report.Evicted += evicted
	report.UploadedSections = append(report.UploadedSections, names...)

	// Log the size on every send: the shared enqueue retry policy drops
	// non-auth 4xx responses, so an oversized payload would otherwise fail
	// permanently and invisibly.
	log.Printf("[telemetry] queued %s envelope: sections=%s bytes=%d evicted=%d",
		sanitize.ForLog(string(class)),
		sanitize.ForLog(strings.Join(names, ",")),
		len(body), evicted)

	if evicted > 0 {
		s.health.AddDropped(evicted)
	}
	return nil
}

// finishHealth stamps queue depth onto the health report.
func (s *Service) finishHealth() *TelemetryHealth {
	if s.queue != nil {
		if depth, err := s.queue.Depth(); err == nil {
			s.health.SetQueueDepth(depth)
		}
	}
	return s.health.Report()
}

// MarkDelivered advances the reconcile clock for sections in a delivered
// message. It is called by the uploader after the backend accepts the payload,
// never at enqueue time: reconcile intervals measure time since the backend
// last saw a section, so queuing alone must not reset them.
func (s *Service) MarkDelivered(sections []string, at time.Time) {
	if s.state == nil {
		return
	}
	for _, name := range sections {
		if err := s.state.MarkUploaded(name, at); err != nil {
			log.Printf("[telemetry] mark uploaded %s: %v", sanitize.ForLog(name), err)
			continue
		}
		s.health.MarkUploaded(name, at)
	}
}

// Health returns the current telemetry health report.
func (s *Service) Health() *TelemetryHealth { return s.finishHealth() }

// itemCount reports the length of a slice-shaped payload, or 1 for a scalar
// section, so the state table records something meaningful for both.
func itemCount(payload any) int {
	switch v := payload.(type) {
	case nil:
		return 0
	case []any:
		return len(v)
	default:
		// Reflection-free approximation: only slices report a count; structs
		// are a single logical item.
		return 1
	}
}

// sortedKeys returns a map's keys in sorted order, so a cycle processes
// sections deterministically.
func sortedKeys(data SectionData) []string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
