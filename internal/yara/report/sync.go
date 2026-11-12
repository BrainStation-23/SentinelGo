package report

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"sentinelgo/internal/service/rpcutil"
	"sentinelgo/internal/store"
	"sentinelgo/internal/supabase"
	"sentinelgo/internal/yara"
)

// ErrRejected is returned by a Sender when the server refused a batch for
// good (22023: one invalid event fails the whole batch, or another
// non-retryable 4xx). The batch is dropped.
var ErrRejected = errors.New("YARA events rejected by the server")

// RPC is the Supabase RPC call (supabase.Client.RPC); an interface so tests
// can fake the server.
type RPC interface {
	RPC(ctx context.Context, fn string, params, out any, opts ...supabase.CallOption) error
}

// Client sends event batches with agent_enqueue_yara_events. client is
// called per request, so each call carries the current access token.
type Client struct {
	client func() RPC
}

// NewClient returns a Client.
func NewClient(client func() RPC) *Client { return &Client{client: client} }

// SendEvents uploads one batch (at most yara.MaxEventsPerCall events) with
// the agent-enqueue retry policy: transient errors are retried until ctx
// ends, a 401 is returned for the caller's DoWithAuthRetry, and a rejected
// batch is ErrRejected.
func (c *Client) SendEvents(ctx context.Context, evs []yara.Event) error {
	if len(evs) > yara.MaxEventsPerCall {
		return fmt.Errorf("report: %d events in one call (max %d)", len(evs), yara.MaxEventsPerCall)
	}
	params := map[string]any{"p_events": evs}
	err := rpcutil.WithEnqueueRetry(rpcutil.ReportDroppedPayloads(ctx), func(ctx context.Context) error {
		var raw []byte
		return c.client().RPC(ctx, yara.RPCEnqueueEvents, params, &raw)
	})
	if errors.Is(err, rpcutil.ErrPayloadDropped) {
		code := ""
		if e, ok := supabase.AsAPIError(err); ok {
			code = e.Code
		}
		return fmt.Errorf("%w (code %q)", ErrRejected, code)
	}
	return err
}

// Sender uploads one batch (Client in production).
type Sender interface {
	SendEvents(ctx context.Context, evs []yara.Event) error
}

// Queue is the on-disk event queue (store.YARAEventStore).
type Queue interface {
	Add(evs []yara.Event) error
	Pending(limit int) ([]store.YARAEventRow, error)
	Delete(ids []int64) error
}

// Retrier runs one server call, recovering an expired session once
// (auth.Service.DoWithAuthRetry in production).
type Retrier func(ctx context.Context, fn func() error) error

// EventSync uploads the queued events. Events stay queued while the device
// is offline and go out once it is back.
type EventSync struct {
	queue  Queue
	sender Sender
	retry  Retrier
}

// NewEventSync returns an EventSync. A nil retry calls the sender directly.
func NewEventSync(q Queue, s Sender, retry Retrier) *EventSync {
	if retry == nil {
		retry = func(_ context.Context, fn func() error) error { return fn() }
	}
	return &EventSync{queue: q, sender: s, retry: retry}
}

// Sync uploads queued events in batches of up to 500 until the queue is
// empty, deleting each batch once the server accepted it. A batch the server
// rejects is dropped and only its event ids are logged; any other error
// leaves the rest queued for the next run. It returns how many events the
// server accepted.
func (e *EventSync) Sync(ctx context.Context) (int, error) {
	sent := 0
	for {
		rows, err := e.queue.Pending(yara.MaxEventsPerCall)
		if err != nil {
			return sent, fmt.Errorf("read YARA event queue: %w", err)
		}
		if len(rows) == 0 {
			return sent, nil
		}
		evs := make([]yara.Event, len(rows))
		ids := make([]int64, len(rows))
		for i, r := range rows {
			evs[i], ids[i] = r.Event, r.ID
		}
		err = e.retry(ctx, func() error { return e.sender.SendEvents(ctx, evs) })
		switch {
		case errors.Is(err, ErrRejected):
			log.Printf("YARA: server rejected a batch of %d events; dropping event ids %s: %v",
				len(evs), eventIDs(evs), err)
		case err != nil:
			return sent, fmt.Errorf("upload YARA events: %w", err)
		default:
			sent += len(evs)
		}
		if err := e.queue.Delete(ids); err != nil {
			return sent, fmt.Errorf("delete uploaded YARA events: %w", err)
		}
		if len(rows) < yara.MaxEventsPerCall {
			return sent, nil
		}
	}
}

// eventIDs lists the batch's event ids for the log: identifiers only.
func eventIDs(evs []yara.Event) string {
	ids := make([]string, len(evs))
	for i, ev := range evs {
		ids[i] = ev.EventID
	}
	return strings.Join(ids, ",")
}
