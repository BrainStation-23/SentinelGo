package dlp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/store"
)

// ErrEventsRejected is returned by an EventSender when the server refused a
// batch for good (a 4xx other than 401/408/429). The batch is dropped.
var ErrEventsRejected = errors.New("DLP events rejected by the server")

// EventQueue is the local evidence queue (store.DLPEventStore).
type EventQueue interface {
	Add(ev events.Event) (merged bool, err error)
	Pending(limit int) ([]store.DLPEventRow, error)
	Delete(ids []int64) error
}

// EventSender uploads one batch (agent_enqueue_dlp_events).
type EventSender interface {
	SendEvents(ctx context.Context, evs []events.Event) error
}

// Batching: rows read per round, and the encoded size one request stays
// under (the server's limit is 1 MB, with room for the envelope).
const (
	eventSyncReadLimit = 500
	eventBatchBytes    = 900 << 10
)

// EventSync uploads the queued evidence. It runs from the dlp-event-sync
// scheduler task.
type EventSync struct {
	queue  EventQueue
	sender EventSender
}

// NewEventSync returns an EventSync.
func NewEventSync(q EventQueue, s EventSender) *EventSync {
	return &EventSync{queue: q, sender: s}
}

// Sync uploads queued events until the queue is empty, deleting each batch
// once the server has enqueued it. A batch the server rejects for good is
// dropped (and logged); any other error leaves the rest queued for the next
// run.
func (e *EventSync) Sync(ctx context.Context) error {
	for {
		rows, err := e.queue.Pending(eventSyncReadLimit)
		if err != nil {
			return fmt.Errorf("read DLP event queue: %w", err)
		}
		if len(rows) == 0 {
			return nil
		}
		for _, batch := range batches(rows) {
			if err := e.send(ctx, batch); err != nil {
				return err
			}
		}
		if len(rows) < eventSyncReadLimit {
			return nil
		}
	}
}

func (e *EventSync) send(ctx context.Context, batch []store.DLPEventRow) error {
	evs := make([]events.Event, len(batch))
	ids := make([]int64, len(batch))
	for i, r := range batch {
		evs[i], ids[i] = r.Event, r.ID
	}
	err := e.sender.SendEvents(ctx, evs)
	switch {
	case errors.Is(err, ErrEventsRejected):
		log.Printf("DLP: server rejected %d evidence events; dropping them: %v", len(batch), err)
	case err != nil:
		return fmt.Errorf("upload DLP events: %w", err)
	}
	if err := e.queue.Delete(ids); err != nil {
		return fmt.Errorf("delete uploaded DLP events: %w", err)
	}
	return nil
}

// batches splits rows into runs whose encoded events stay under
// eventBatchBytes. An event too big on its own still gets its own batch (the
// server then rejects it, and it is dropped).
func batches(rows []store.DLPEventRow) [][]store.DLPEventRow {
	var out [][]store.DLPEventRow
	var cur []store.DLPEventRow
	size := 0
	for _, r := range rows {
		data, _ := json.Marshal(r.Event)
		n := len(data) + 1 // comma
		if len(cur) > 0 && size+n > eventBatchBytes {
			out = append(out, cur)
			cur, size = nil, 0
		}
		cur = append(cur, r)
		size += n
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// queueSink is the channel.EventSink that puts events in the local queue.
type queueSink struct{ q EventQueue }

// NewQueueSink returns a sink that queues events for upload. Failures are
// logged without the event's content (it carries none beyond masked
// findings, but the log stays content-free regardless).
func NewQueueSink(q EventQueue) channel.EventSink { return queueSink{q: q} }

func (s queueSink) Emit(ev events.Event) {
	if _, err := s.q.Add(ev); err != nil {
		log.Printf("DLP: could not queue event %s (policy %s): %v", ev.EventID, ev.PolicyID, err)
	}
}
