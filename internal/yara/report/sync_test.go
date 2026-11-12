package report

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"testing"

	"sentinelgo/internal/store"
	"sentinelgo/internal/supabase"
	"sentinelgo/internal/yara"
)

func summary(i int) yara.Event {
	return yara.Event{EventID: fmt.Sprintf("0d9e8f7a-4444-4b6c-9d0e-%012d", i), Summary: &yara.ScanSummary{
		ScanID: "a0b1c2d3-3333-4e5f-8a9b-0123456789ab", Trigger: yara.TriggerScheduled, State: yara.ScanCompleted,
	}}
}

func newQueue(t *testing.T) *store.YARAEventStore {
	t.Helper()
	q, err := store.NewYARAEventStore(filepath.Join(t.TempDir(), store.YARAEventsDBName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = q.Close() })
	return q
}

// fakeRPC answers agent_enqueue_yara_events with the queued errors, then
// success, and records each call's events.
type fakeRPC struct {
	errs  []error
	calls [][]yara.Event
	raw   [][]byte
	// onErr runs when a queued error is returned (e.g. the device goes
	// offline for good: cancel the sync).
	onErr func()
}

func (f *fakeRPC) RPC(_ context.Context, fn string, params, _ any, _ ...supabase.CallOption) error {
	if fn != yara.RPCEnqueueEvents {
		return fmt.Errorf("unexpected RPC %s", fn)
	}
	evs := params.(map[string]any)["p_events"].([]yara.Event)
	f.calls = append(f.calls, evs)
	data, _ := json.Marshal(params)
	f.raw = append(f.raw, data)
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		if f.onErr != nil {
			f.onErr()
		}
		return err
	}
	return nil
}

func apiErr(status int, code string) error {
	return &supabase.APIError{Status: status, Code: code, Message: "m"}
}

func TestSync_OfflineThenReconnect(t *testing.T) {
	q := newQueue(t)
	var evs []yara.Event
	for i := range 1200 {
		evs = append(evs, summary(i))
	}
	if err := q.Add(evs); err != nil {
		t.Fatal(err)
	}
	// Offline: the network call fails and the sync ends (here: its
	// context is cancelled during that call, so the retry backoff stops);
	// everything stays queued. No timing involved, so -race can't flake it.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rpc := &fakeRPC{errs: []error{errors.New("dial tcp: no route to host")}, onErr: cancel}
	sync := NewEventSync(q, NewClient(func() RPC { return rpc }), nil)
	if _, err := sync.Sync(ctx); err == nil {
		t.Fatal("offline sync succeeded")
	}
	if n, _, _, _ := q.Stats(); n != 1200 || len(rpc.calls) != 1 {
		t.Fatalf("%d queued after failing offline (want 1200), %d calls (want 1)", n, len(rpc.calls))
	}
	// Back online: three batches of at most 500, queue empty.
	rpc.errs = nil
	sent, err := sync.Sync(context.Background())
	if err != nil || sent != 1200 {
		t.Fatalf("sent %d, %v", sent, err)
	}
	var sizes []int
	for _, c := range rpc.calls[1:] {
		sizes = append(sizes, len(c))
	}
	if fmt.Sprint(sizes) != "[500 500 200]" {
		t.Fatalf("batches = %v", sizes)
	}
	if n, _, _, _ := q.Stats(); n != 0 {
		t.Fatalf("%d left in the queue", n)
	}
}

// A 401 is handed to the caller's DoWithAuthRetry, which recovers the
// session once and calls again.
func TestSync_401RecoversOnce(t *testing.T) {
	q := newQueue(t)
	_ = q.Add([]yara.Event{summary(1)})
	rpc := &fakeRPC{errs: []error{apiErr(401, "PGRST301")}}
	recovered := 0
	retry := func(_ context.Context, fn func() error) error {
		err := fn()
		if supabase.IsUnauthorized(err) {
			recovered++
			err = fn()
		}
		return err
	}
	sent, err := NewEventSync(q, NewClient(func() RPC { return rpc }), retry).Sync(context.Background())
	if err != nil || sent != 1 || recovered != 1 || len(rpc.calls) != 2 {
		t.Fatalf("sent %d, err %v, recovered %d, calls %d", sent, err, recovered, len(rpc.calls))
	}
}

// 22023 drops the batch and logs the event ids only.
func TestSync_22023DropsBatchLogsIDsOnly(t *testing.T) {
	q := newQueue(t)
	ev := summary(7)
	ev.Summary.ScanID = "a0b1c2d3-3333-4e5f-8a9b-0123456789ab"
	_ = q.Add([]yara.Event{ev, summary(8)})
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old) })

	rpc := &fakeRPC{errs: []error{apiErr(400, yara.SQLStateInvalid)}}
	sent, err := NewEventSync(q, NewClient(func() RPC { return rpc }), nil).Sync(context.Background())
	if err != nil || sent != 0 || len(rpc.calls) != 1 {
		t.Fatalf("sent %d, err %v, calls %d", sent, err, len(rpc.calls))
	}
	if n, _, _, _ := q.Stats(); n != 0 {
		t.Fatalf("rejected batch still queued (%d)", n)
	}
	out := buf.String()
	if !strings.Contains(out, ev.EventID) || !strings.Contains(out, summary(8).EventID) {
		t.Errorf("log lacks the event ids: %s", out)
	}
	if strings.Contains(out, ev.Summary.ScanID) || strings.Contains(out, "scan_summary") {
		t.Errorf("log carries event bodies: %s", out)
	}
}

func TestClient_RefusesOversizedBatch(t *testing.T) {
	evs := make([]yara.Event, yara.MaxEventsPerCall+1)
	if err := NewClient(func() RPC { return &fakeRPC{} }).SendEvents(context.Background(), evs); err == nil {
		t.Fatal("sent more than 500 events in one call")
	}
}
