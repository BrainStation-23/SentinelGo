package telemetry

import (
	"encoding/json"
	"fmt"
	"log"
	"runtime"

	"sentinelgo/internal/config"
	"sentinelgo/internal/models"
	"sentinelgo/internal/sanitize"
)

// maxEventsPerMessage bounds how many events travel in one queued message.
//
// Events are small (a few hundred bytes each), so this is well inside the
// payload cap; the reason to bound it at all is that one message is one
// all-or-nothing delivery. A single message carrying a whole cycle's worth of
// events would mean one backend rejection dead-letters every event in it.
const maxEventsPerMessage = 50

// detectChanges runs Phase G against data that has already been collected and
// enqueues whatever events come out of it.
//
// It is a no-op when no engine is configured, which is the shipped default.
func (s *Service) detectChanges(cfg *config.Config, data SectionData, results []CollectorResult, report *CycleReport) error {
	if s.events == nil {
		return nil
	}

	deviceID, agentVersion := "", ""
	if cfg != nil {
		deviceID, agentVersion = cfg.DeviceID, cfg.CurrentVersion
	}

	result, err := s.events.Process(deviceID, agentVersion, data, StatusesFrom(results))
	if err != nil {
		return err
	}

	report.Events = result.Events
	report.EventsSeeded = len(result.Seeded)
	report.EventsSuppressed = len(result.Suppressed)
	for _, e := range result.Events {
		if e.Priority.Immediate() {
			report.CriticalEvents++
		}
	}

	if len(result.Seeded) > 0 {
		// Seeding is the one-off cost of enabling the feature (or of a new
		// watch key shipping), and saying so explicitly is what stops "no
		// events on the first cycle" being read as the feature not working.
		log.Printf("[telemetry] change detection seeded %d baseline value(s); no events by design",
			len(result.Seeded))
	}
	if len(result.Events) == 0 {
		return nil
	}

	log.Printf("[telemetry] change detection: events=%d suppressed=%d skipped_sections=%d types=%s",
		len(result.Events), len(result.Suppressed), len(result.SkippedSections),
		sanitize.ForLog(SummarizeEvents(result.Events)))

	return s.enqueueEvents(cfg, result.Events, report)
}

// enqueueEvents batches events onto the existing durable outbound queue.
//
// Two properties are load-bearing:
//
//   - Class is ClassEvent, which is how the sender picks the events RPC rather
//     than the section one. Nothing else distinguishes them on the queue.
//   - Sections is EMPTY. The delivery path advances a section's reconcile clock
//     for every section a delivered message names, so an event message that
//     named its source section would mark that section as reconciled without
//     the backend ever having received it — and the section's real data would
//     then sit unsent until its next content change.
func (s *Service) enqueueEvents(cfg *config.Config, events []models.TelemetryChangeEvent, report *CycleReport) error {
	if s.queue == nil {
		return nil
	}

	for _, batch := range batchEvents(events) {
		body, err := marshalEventEnvelope(cfg, batch)
		if err != nil {
			return err
		}

		if len(body) > MaxPayloadBytes {
			// Should be unreachable given maxEventsPerMessage, but a queued
			// oversize payload fails permanently at the backend, so it is
			// logged rather than left to be discovered as a dead letter.
			log.Printf("[telemetry] event message is %d bytes, over the %d cap",
				len(body), MaxPayloadBytes)
		}

		if err := s.queueMessage(QueuedMessage{
			SnapshotID: NewSnapshotID(),
			Sections:   nil,
			Class:      ClassEvent,
			Priority:   int(batch[0].Priority),
			BatchIndex: 0,
			BatchCount: 1,
			Payload:    body,
		}, report); err != nil {
			return err
		}
	}

	return nil
}

// batchEvents groups events into messages of a single priority.
//
// Grouping by priority is what makes the queue's ordering meaningful: the queue
// sorts by the message's priority column, so mixing a critical event into a
// batch of routine ones would either delay the critical event or promote the
// routine ones. Events arrive already sorted most-urgent-first.
func batchEvents(events []models.TelemetryChangeEvent) [][]models.TelemetryChangeEvent {
	var batches [][]models.TelemetryChangeEvent
	var current []models.TelemetryChangeEvent

	flush := func() {
		if len(current) > 0 {
			batches = append(batches, current)
			current = nil
		}
	}

	for _, e := range events {
		if len(current) > 0 && (current[0].Priority != e.Priority || len(current) >= maxEventsPerMessage) {
			flush()
		}
		current = append(current, e)
	}
	flush()
	return batches
}

// marshalEventEnvelope renders one batch for the wire.
func marshalEventEnvelope(cfg *config.Config, events []models.TelemetryChangeEvent) ([]byte, error) {
	env := EventEnvelope{
		SchemaVersion: EventSchemaVersion,
		Platform:      runtime.GOOS,
		Events:        events,
	}
	if cfg != nil {
		env.DeviceID = cfg.DeviceID
		env.AgentVersion = cfg.CurrentVersion
	}

	body, err := json.Marshal(map[string]any{"payload": env})
	if err != nil {
		return nil, fmt.Errorf("telemetry: marshal event envelope: %w", err)
	}
	// Postgres rejects NUL bytes in text/jsonb; strip any that reached a value.
	return sanitize.StripJSONNUL(body), nil
}
