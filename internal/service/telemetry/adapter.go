// Package telemetry wires the telemetry domain layer (internal/telemetry) to
// the agent's concrete stores, scheduler and transport.
//
// The domain package is deliberately free of database and HTTP dependencies so
// its cycle logic can be tested without either. This package supplies the
// adapters that connect it to the real SQLite stores.
package telemetry

import (
	"strings"
	"time"

	tel "sentinelgo/internal/telemetry"

	"sentinelgo/internal/store"
)

// stateAdapter adapts the SQLite section-state store to tel.StateStore.
type stateAdapter struct {
	s *store.TelemetryStateStore
}

func (a stateAdapter) GetAll() (map[string]*tel.SectionState, error) {
	rows, err := a.s.GetAll()
	if err != nil {
		return nil, err
	}
	out := make(map[string]*tel.SectionState, len(rows))
	for name, r := range rows {
		out[name] = &tel.SectionState{
			Section:          r.Section,
			SchemaVersion:    r.SchemaVersion,
			Hash:             r.Hash,
			ItemCount:        r.ItemCount,
			Status:           r.Status,
			LastCollectedAt:  r.LastCollectedAt,
			LastUploadedAt:   r.LastUploadedAt,
			LastReconciledAt: r.LastReconciledAt,
		}
	}
	return out, nil
}

func (a stateAdapter) NextCollectionGeneration() (uint64, error) {
	return a.s.NextCollectionGeneration()
}

func (a stateAdapter) MarkCollected(section string, schemaVersion int, hash string, itemCount int, status string, at time.Time) error {
	return a.s.MarkCollected(section, schemaVersion, hash, itemCount, status, at)
}

func (a stateAdapter) MarkUploaded(section string, at time.Time) error {
	return a.s.MarkUploaded(section, at)
}

// queueAdapter adapts the SQLite outbound queue to tel.OutboundQueue.
type queueAdapter struct {
	q *store.TelemetryOutboundStore
}

// sectionSeparator joins the section list into the queue's single section
// column. Delivery splits it again so exactly the carried sections have their
// reconcile clocks advanced.
const sectionSeparator = ","

func (a queueAdapter) Enqueue(msg tel.QueuedMessage) (int64, error) {
	return a.q.Enqueue(store.OutboundMessage{
		SnapshotID: msg.SnapshotID,
		Section:    strings.Join(msg.Sections, sectionSeparator),
		Class:      string(msg.Class),
		Priority:   msg.Priority,
		BatchIndex: msg.BatchIndex,
		BatchCount: msg.BatchCount,
		Payload:    string(msg.Payload),
		ByteSize:   len(msg.Payload),
	})
}

func (a queueAdapter) Depth() (int, error) { return a.q.Depth() }

// SectionsOf splits a queued message's section column back into a list.
func SectionsOf(msg store.OutboundMessage) []string {
	if msg.Section == "" {
		return nil
	}
	return strings.Split(msg.Section, sectionSeparator)
}
