package telemetry

import (
	"context"
	"encoding/json"
	"errors"
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
	NextCollectionGeneration() (uint64, error)
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
	// Truncated lists sections where at least one item was too large to send.
	Truncated []string

	// Data is this cycle's section payloads, exposed so change detection can
	// compare values that were ALREADY collected.
	//
	// Exposing it is what keeps Phase G free: the alternative is a second
	// collection pass to read the same firewall state the posture cycle just
	// read, which would double the endpoint cost of every watched section and
	// introduce a window in which the two passes disagree.
	//
	// It is not sent anywhere. Only the sections that changed or are due for
	// reconciliation are enqueued, exactly as before.
	Data SectionData

	// Events is the change events this cycle produced, already enqueued.
	Events []models.TelemetryChangeEvent
	// EventsSeeded counts watch keys whose baseline was established this cycle.
	// A seeded key produces no event, by design.
	EventsSeeded int
	// EventsSuppressed counts transitions withheld by debounce, cooldown or
	// flap detection.
	EventsSuppressed int
	// CriticalEvents counts events that must reach the backend immediately.
	CriticalEvents int
}

// Service runs telemetry collection cycles.
type Service struct {
	registry *Registry
	set      *CollectorSet
	state    StateStore
	queue    OutboundQueue
	health   *HealthTracker

	// events is Phase G's change-detection engine, or nil.
	//
	// Nil is the shipped default and means the cycle behaves exactly as it did
	// before Phase G existed: no watched state is read or written, no events
	// are produced, and nothing new is enqueued. Feature gating is this field
	// being nil, not a flag checked in ten places.
	events *EventEngine

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
	if s.events != nil && fn != nil {
		s.events.SetClock(fn)
	}
}

// SetEventEngine enables Phase G change detection. Passing nil disables it.
func (s *Service) SetEventEngine(engine *EventEngine) {
	s.events = engine
	if engine != nil {
		engine.SetClock(s.now)
	}
}

// EventEngine returns the configured change-detection engine, or nil.
func (s *Service) EventEngine() *EventEngine { return s.events }

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

	data, results, caps, sectionCaps := RunAll(ctx, s.set, CollectorConfigFrom(cfg))

	report := &CycleReport{
		Reasons:      make(map[string]string),
		Results:      results,
		Capabilities: caps,
		Data:         data,
	}

	// Indexed by section, not by capability key: a section's key (when it has
	// one at all) is not always the section's own name — see RunAll's doc
	// comment — so looking this up in the capability manifest itself would
	// silently mis-report "not_applicable" for every section whose name and
	// key differ.
	for _, res := range results {
		s.health.Observe(res, sectionCaps[res.Section])
	}

	if len(data) == 0 {
		report.Health = s.finishHealth()
		return report, nil
	}

	// Change detection runs before section upload and is independent of it.
	//
	// The order matters in one direction only: a change event must be produced
	// from what was collected regardless of whether the section itself is due
	// for upload. Most cycles upload nothing (that is the point of
	// reconciliation), and a firewall being switched off is exactly the kind of
	// change that would otherwise wait hours for its section's reconcile clock.
	if err := s.detectChanges(cfg, data, results, report); err != nil {
		// Change detection failing must not cost the cycle its inventory. Log
		// and continue: the sections below are still worth sending, and the
		// watched state is left untouched so the next cycle retries from the
		// same baseline rather than re-seeding.
		log.Printf("[telemetry] change detection failed, continuing with section upload: %v", err)
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
		generation, genErr := s.nextCollectionGeneration()
		if genErr != nil {
			return report, genErr
		}
		if err := s.enqueue(cfg, upload, data, now, generation, report); err != nil {
			return report, err
		}
	}

	report.Health = s.finishHealth()
	return report, nil
}

func (s *Service) nextCollectionGeneration() (uint64, error) {
	if s.state == nil {
		return 0, nil
	}
	generation, err := s.state.NextCollectionGeneration()
	if err != nil {
		return 0, fmt.Errorf("telemetry: allocate collection generation: %w", err)
	}
	return generation, nil
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
// Non-chunked sections of the same class travel together in one envelope.
// Chunked sections get their own envelopes so a large list can be split without
// dragging unrelated sections into every batch.
func (s *Service) enqueue(
	cfg *config.Config,
	upload []string,
	data SectionData,
	now time.Time,
	generation uint64,
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
		if err := s.enqueueEnvelope(cfg, class, names, data, now, generation, report); err != nil {
			return err
		}
	}

	for _, name := range chunked {
		if err := s.enqueueChunked(cfg, name, data[name], now, generation, report); err != nil {
			return err
		}
	}
	return nil
}

// newEnvelopeFor builds an envelope pre-populated with this cycle capabilities
// and diagnostics.
func (s *Service) newEnvelopeFor(cfg *config.Config, class Class, now time.Time, generation uint64, report *CycleReport) *Envelope {
	env := NewEnvelope(cfg, class, now)
	env.CollectionGeneration = generation
	env.Capabilities = report.Capabilities.Clone()
	env.Meta = &Meta{Results: report.Results, Health: s.health.Report()}
	return env
}

// marshalEnvelope renders an envelope for the wire.
func marshalEnvelope(env *Envelope) ([]byte, error) {
	env.Finalize()
	body, err := json.Marshal(map[string]any{"payload": env})
	if err != nil {
		return nil, fmt.Errorf("telemetry: marshal envelope: %w", err)
	}
	// Postgres rejects NUL bytes in text/jsonb; strip any that survived collection.
	return sanitize.StripJSONNUL(body), nil
}

// enqueueEnvelope builds and queues one envelope for the given sections.
func (s *Service) enqueueEnvelope(
	cfg *config.Config,
	class Class,
	names []string,
	data SectionData,
	now time.Time,
	generation uint64,
	report *CycleReport,
) error {
	env := s.newEnvelopeFor(cfg, class, now, generation, report)
	for _, name := range names {
		spec, _ := s.registry.Get(name)
		env.AddSection(name, spec.SchemaVersion, data[name])
	}

	body, err := marshalEnvelope(env)
	if err != nil {
		return err
	}

	return s.queueMessage(QueuedMessage{
		SnapshotID: NewSnapshotID(),
		Sections:   names,
		Class:      class,
		Priority:   int(models.PriorityNormal),
		BatchIndex: 0,
		BatchCount: 1,
		Payload:    body,
	}, report)
}

// chunkBudget measures how many bytes of section items fit in one message once
// the envelope wrapper, capability manifest and diagnostics are accounted for.
//
// Measuring rather than guessing matters: the capability manifest and per-cycle
// results run to several kilobytes, so a fixed guess would either waste headroom
// or produce batches that exceed the cap once wrapped.
func (s *Service) chunkBudget(cfg *config.Config, spec SectionSpec, name string, now time.Time, generation uint64, report *CycleReport) int {
	probe := s.newEnvelopeFor(cfg, spec.Class, now, generation, report)
	probe.AddSection(name, spec.SchemaVersion, []any{})
	probe.Chunk = ChunkMetaFor(NewSnapshotID(), 0, 1, 0, 0)

	body, err := marshalEnvelope(probe)
	if err != nil {
		return MaxPayloadBytes / 2
	}

	budget := MaxPayloadBytes - len(body) - envelopeOverheadMargin
	if budget < 1024 {
		budget = 1024
	}
	return budget
}

// enqueueChunked splits a high-cardinality section across as many messages as it
// needs, all sharing one snapshot_id.
//
// Every batch of a snapshot is queued together with that snapshot_id stored
// alongside it, so a delivery retry replays the stored message rather than
// generating a fresh id. The backend therefore never sees two logical snapshots
// for one collection.
func (s *Service) enqueueChunked(
	cfg *config.Config,
	name string,
	payload any,
	now time.Time,
	generation uint64,
	report *CycleReport,
) error {
	spec, ok := s.registry.Get(name)
	if !ok {
		return nil
	}

	budget := s.chunkBudget(cfg, spec, name, now, generation, report)

	batches, totalItems, oversized, err := ChunkSection(payload, budget)
	if err != nil {
		if errors.Is(err, ErrNotChunkable) {
			// The section is declared chunked but produced a scalar. Send it as a
			// single envelope rather than failing the cycle.
			log.Printf("[telemetry] section %s is marked chunked but is not a list; sending unsplit",
				sanitize.ForLog(name))
			return s.enqueueEnvelope(cfg, spec.Class, []string{name}, SectionData{name: payload}, now, generation, report)
		}
		return fmt.Errorf("telemetry: chunk section %q: %w", name, err)
	}

	if len(oversized) > 0 {
		// Never silent: an item too large for any batch is reported in the
		// payload, in the log, and in telemetry health.
		log.Printf("[telemetry] section %s: %d item(s) exceed the %d-byte budget and cannot be sent; snapshot marked truncated",
			sanitize.ForLog(name), len(oversized), budget)
		s.health.AddDropped(int64(len(oversized)))
		report.Truncated = append(report.Truncated, name)
	}

	if len(batches) == 0 {
		// An explicitly collected empty list is authoritative. It must become a
		// one-chunk empty snapshot; sending nothing would leave the previous
		// generation visible forever. The same representation safely records a
		// fully-excluded truncated snapshot.
		batches = [][]any{{}}
	}

	snapshotID := NewSnapshotID()
	batchCount := len(batches)

	for i, batch := range batches {
		env := s.newEnvelopeFor(cfg, spec.Class, now, generation, report)
		env.AddSection(name, spec.SchemaVersion, batch)
		env.Chunk = ChunkMetaFor(snapshotID, i, batchCount, totalItems, len(oversized))

		body, mErr := marshalEnvelope(env)
		if mErr != nil {
			return mErr
		}
		if len(body) > MaxPayloadBytes {
			// The budget should prevent this. If it happens the batch is still
			// queued rather than dropped, and the oversize is logged so it can be
			// diagnosed instead of failing invisibly at the backend.
			log.Printf("[telemetry] section %s batch %d/%d is %d bytes, over the %d cap",
				sanitize.ForLog(name), i+1, batchCount, len(body), MaxPayloadBytes)
		}

		if qErr := s.queueMessage(QueuedMessage{
			SnapshotID: snapshotID,
			Sections:   []string{name},
			Class:      spec.Class,
			Priority:   int(models.PriorityNormal),
			BatchIndex: i,
			BatchCount: batchCount,
			Payload:    body,
		}, report); qErr != nil {
			return qErr
		}
	}

	log.Printf("[telemetry] section %s chunked into %d batch(es): items=%d excluded=%d snapshot=%s",
		sanitize.ForLog(name), batchCount, totalItems, len(oversized), snapshotID)
	return nil
}

// queueMessage enqueues one prepared message and records it in the report.
func (s *Service) queueMessage(msg QueuedMessage, report *CycleReport) error {
	evicted, err := s.queue.Enqueue(msg)
	if err != nil {
		return fmt.Errorf("telemetry: enqueue %s message: %w", msg.Class, err)
	}

	report.Messages++
	report.Evicted += evicted
	for _, name := range msg.Sections {
		if !containsString(report.UploadedSections, name) {
			report.UploadedSections = append(report.UploadedSections, name)
		}
	}

	// Log the size on every send: the shared enqueue retry policy drops non-auth
	// 4xx responses, so an oversized payload would otherwise fail permanently and
	// invisibly.
	log.Printf("[telemetry] queued %s message: sections=%s batch=%d/%d bytes=%d evicted=%d",
		sanitize.ForLog(string(msg.Class)),
		sanitize.ForLog(strings.Join(msg.Sections, ",")),
		msg.BatchIndex+1, msg.BatchCount, len(msg.Payload), evicted)

	if evicted > 0 {
		s.health.AddDropped(evicted)
	}
	return nil
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
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
