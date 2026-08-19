package telemetry

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"time"

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

	return &Service{
		cfg:        cfg,
		stateStore: stateStore,
		queueStore: queueStore,
		domain:     domain,
	}, nil
}

// Domain exposes the cycle runner, for CLI commands and tests.
func (s *Service) Domain() *tel.Service { return s.domain }

// RunCycle executes one collection and reconciliation cycle.
func (s *Service) RunCycle(ctx context.Context) (*tel.CycleReport, error) {
	return s.domain.RunCycle(ctx, s.cfg)
}

// Health returns the current telemetry health report, including queue depth.
func (s *Service) Health() *tel.TelemetryHealth { return s.domain.Health() }

// QueueDepth returns the number of queued telemetry messages.
func (s *Service) QueueDepth() (int, error) { return s.queueStore.Depth() }

// QueueBytes returns the queue's current payload size.
func (s *Service) QueueBytes() (int64, error) { return s.queueStore.TotalBytes() }

// Pending returns up to limit queued messages, most urgent first.
func (s *Service) Pending(limit int) ([]store.OutboundMessage, error) {
	return s.queueStore.GetPending(limit)
}

// MarkDelivered removes delivered messages from the queue and advances the
// reconcile clock for exactly the sections they carried.
//
// Delivery, not enqueue, is what advances reconciliation: the interval measures
// how long it has been since the backend saw a section, so a message sitting in
// the queue must not count as delivered.
func (s *Service) MarkDelivered(msgs []store.OutboundMessage, at time.Time) error {
	if len(msgs) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(msgs))
	for _, m := range msgs {
		ids = append(ids, m.ID)
	}
	if err := s.queueStore.Delete(ids); err != nil {
		return fmt.Errorf("telemetry: delete delivered messages: %w", err)
	}
	for _, m := range msgs {
		s.domain.MarkDelivered(SectionsOf(m), at)
	}
	return nil
}

// ResetState clears reconciliation state, forcing a full resync next cycle.
func (s *Service) ResetState() error { return s.stateStore.Reset() }

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
	log.Printf("[telemetry] cycle: collected=%d uploaded=%d skipped=%d messages=%d evicted=%d",
		len(report.CollectedSections), len(report.UploadedSections),
		len(report.SkippedSections), report.Messages, report.Evicted)

	for _, section := range report.SkippedSections {
		log.Printf("[telemetry] section %s skipped (%s)",
			sanitize.ForLog(section), sanitize.ForLog(report.Reasons[section]))
	}
}
