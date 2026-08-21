package telemetry

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"path/filepath"

	tel "sentinelgo/internal/telemetry"

	"sentinelgo/internal/config"
	"sentinelgo/internal/sanitize"
	"sentinelgo/internal/store"
)

// Service owns the telemetry stores and the domain cycle runner for the
// lifetime of the agent process.
type Service struct {
	cfg        *config.Config
	stateStore *store.TelemetryStateStore
	queueStore *store.TelemetryOutboundStore
	domain     *tel.Service
	client     *http.Client
}

// StateDBPath returns the telemetry state database path, placed alongside
// config.json like the other agent stores.
func StateDBPath(cfg *config.Config) string {
	return filepath.Join(filepath.Dir(cfg.Path), store.TelemetryStateDBName)
}

// QueueDBPath returns the telemetry outbound queue database path.
func QueueDBPath(cfg *config.Config) string {
	return filepath.Join(filepath.Dir(cfg.Path), store.TelemetryOutboundDBName)
}

// New opens the telemetry stores and builds the service.
//
// Collectors are registered separately: this phase ships the foundation, and
// an empty collector set produces no sections and no traffic, which is exactly
// what "enabled but nothing to collect yet" should do.
func New(cfg *config.Config, set *tel.CollectorSet) (*Service, error) {
	stateStore, err := store.NewTelemetryStateStore(StateDBPath(cfg))
	if err != nil {
		return nil, fmt.Errorf("telemetry: open state store: %w", err)
	}

	limits := store.OutboundLimits{
		MaxAge:   cfg.GetTelemetryQueueMaxAge(),
		MaxRows:  cfg.GetTelemetryQueueMaxRows(),
		MaxBytes: cfg.GetTelemetryQueueMaxBytes(),
	}
	queueStore, err := store.NewTelemetryOutboundStore(QueueDBPath(cfg), limits)
	if err != nil {
		_ = stateStore.Close()
		return nil, fmt.Errorf("telemetry: open outbound queue: %w", err)
	}

	domain := tel.NewService(
		tel.NewDefaultRegistry(),
		set,
		stateAdapter{s: stateStore},
		queueAdapter{q: queueStore},
	)

	if err := attachEventEngine(cfg, domain, stateStore); err != nil {
		_ = queueStore.Close()
		_ = stateStore.Close()
		return nil, err
	}

	return &Service{
		cfg:        cfg,
		stateStore: stateStore,
		queueStore: queueStore,
		domain:     domain,
		client:     newHTTPClient(),
	}, nil
}

// attachEventEngine enables Phase G when configuration asks for it.
//
// A configuration error is fatal to telemetry startup rather than silently
// corrected. Change detection drives security alerting, and a cooldown longer
// than the flapping window (say) would suppress events in a way nobody would
// notice until an incident was missed — the failure mode a default would hide.
func attachEventEngine(cfg *config.Config, domain *tel.Service, stateStore *store.TelemetryStateStore) error {
	if cfg == nil || !cfg.TelemetryEventsEnabled {
		log.Printf("[telemetry] change detection disabled (telemetry_events_enabled=false)")
		return nil
	}

	eventCfg := tel.EventConfig{
		Debounce:      cfg.GetTelemetryEventDebounce(),
		Cooldown:      cfg.GetTelemetryEventCooldown(),
		FlapWindow:    cfg.GetTelemetryEventFlapWindow(),
		FlapThreshold: cfg.GetTelemetryEventFlapThreshold(),
	}
	if err := eventCfg.Validate(); err != nil {
		return fmt.Errorf("telemetry: invalid event configuration: %w", err)
	}

	domain.SetEventEngine(tel.NewEventEngine(
		tel.DefaultWatches(),
		watchedStateAdapter{s: stateStore},
		eventCfg,
	))

	log.Printf("[telemetry] change detection enabled: watches=%d debounce=%v cooldown=%v flap=%d/%v",
		len(tel.DefaultWatches()), eventCfg.Debounce, eventCfg.Cooldown,
		eventCfg.FlapThreshold, eventCfg.FlapWindow)
	return nil
}

// WatchedStateDepth returns how many watched values are persisted.
func (s *Service) WatchedStateDepth() (int, error) { return s.stateStore.WatchedDepth() }

// EventsEnabled reports whether Phase G change detection is active.
func (s *Service) EventsEnabled() bool { return s.domain.EventEngine() != nil }

// Domain exposes the cycle runner, for CLI commands and tests.
func (s *Service) Domain() *tel.Service { return s.domain }

// RunCycle executes one collection and reconciliation cycle.
func (s *Service) RunCycle(ctx context.Context) (*tel.CycleReport, error) {
	return s.domain.RunCycle(ctx, s.cfg)
}

// Health returns the current telemetry health report, including queue depth.
func (s *Service) Health() *tel.TelemetryHealth { return s.domain.Health() }

// QueueDepth returns the number of deliverable queued telemetry messages.
func (s *Service) QueueDepth() (int, error) { return s.queueStore.Depth() }

// DeadLetterDepth returns how many undeliverable messages are retained.
func (s *Service) DeadLetterDepth() (int, error) { return s.queueStore.DeadLetterDepth() }

// DeadLettered returns retained undeliverable messages for inspection.
func (s *Service) DeadLettered(limit int) ([]store.OutboundMessage, error) {
	return s.queueStore.ListDeadLettered(limit)
}

// QueueBytes returns the queue's current payload size.
func (s *Service) QueueBytes() (int64, error) { return s.queueStore.TotalBytes() }

// Pending returns up to limit queued messages, most urgent first.
func (s *Service) Pending(limit int) ([]store.OutboundMessage, error) {
	return s.queueStore.GetPending(limit)
}

// ResetState clears telemetry reconciliation state and the outbound queue,
// forcing a full resync on the next cycle.
//
// Scope is deliberately narrow: it touches ONLY the two telemetry databases.
// Device registration, credentials, agent identity, the software and services
// catalogs, the audit-log queue and the task store are all left untouched, so
// this is safe to run on a live agent to recover from a bad telemetry state.
func (s *Service) ResetState() error {
	if err := s.stateStore.Reset(); err != nil {
		return fmt.Errorf("telemetry: reset section state: %w", err)
	}
	cleared, err := s.queueStore.Clear()
	if err != nil {
		return fmt.Errorf("telemetry: clear outbound queue: %w", err)
	}
	log.Printf("[telemetry] reset: section state cleared, %d queued message(s) discarded", cleared)
	return nil
}

// Close releases both database handles.
func (s *Service) Close() error {
	var firstErr error
	if s.queueStore != nil {
		if err := s.queueStore.Close(); err != nil {
			firstErr = err
		}
	}
	if s.stateStore != nil {
		if err := s.stateStore.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// LogCycle emits a one-line summary of a cycle.
func LogCycle(report *tel.CycleReport) {
	if report == nil {
		return
	}
	log.Printf("[telemetry] cycle: collected=%d uploaded=%d skipped=%d messages=%d evicted=%d events=%d critical=%d seeded=%d suppressed=%d",
		len(report.CollectedSections), len(report.UploadedSections),
		len(report.SkippedSections), report.Messages, report.Evicted,
		len(report.Events), report.CriticalEvents,
		report.EventsSeeded, report.EventsSuppressed)

	for _, section := range report.SkippedSections {
		log.Printf("[telemetry] section %s skipped (%s)",
			sanitize.ForLog(section), sanitize.ForLog(report.Reasons[section]))
	}
}
