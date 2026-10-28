package dlp

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/dlp"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/store"
	"sentinelgo/internal/supabase"
	"sentinelgo/internal/supabase/supabasetest"
)

const eventsPath = "/rest/v1/rpc/agent_enqueue_dlp_events"

const enqueued = `{"success":true,"enqueued":true,"agent_id":"a","queue":"agent_ingest_dlp_events","msg_id":7}`

func newQueue(t *testing.T) *store.DLPEventStore {
	t.Helper()
	q, err := store.NewDLPEventStore(filepath.Join(t.TempDir(), store.DLPEventsDBName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = q.Close() })
	return q
}

func sampleEvent(content string) events.Event {
	return events.Event{
		EventID: events.NewID(), OccurredAt: time.Unix(1_700_000_000, 0).UTC(), Channel: "clipboard",
		PolicyID: "p1", PolicyVersion: "v1", Action: events.ActionBlocked, Severity: "high",
		User: `CORP\alice`, SessionID: "2", SourceApp: events.SourceApp{Name: "chrome.exe"},
		Findings:      []events.Finding{{Detector: "secrets.github-pat", Count: 1, Masked: "ghp_****wxyz", SHA256: "h"}},
		ContentLength: 40, ContentSHA256: content, RepeatCount: 1,
	}
}

func pending(t *testing.T, q *store.DLPEventStore) int {
	t.Helper()
	n, _, _, err := q.Stats()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// Round trip: an event emitted into the sink is queued, uploaded in the
// contract's {"payload":{"events":[…]}} shape, and deleted once enqueued.
func TestEventRoundTrip(t *testing.T) {
	fake := supabasetest.New(t)
	fake.Handle(http.MethodPost, eventsPath, supabasetest.Response{Status: 200, Body: enqueued})
	q := newQueue(t)

	sink := dlp.NewQueueSink(q)
	sink.Emit(sampleEvent("c1"))
	sink.Emit(sampleEvent("c1")) // repeat: merged
	sink.Emit(sampleEvent("c2"))

	if err := dlp.NewEventSync(q, newService(fake)).Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if n := pending(t, q); n != 0 {
		t.Errorf("%d rows left after upload", n)
	}

	reqs := fake.Requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %d, want 1 batch", len(reqs))
	}
	var body struct {
		Payload struct {
			Events []events.Event `json:"events"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(reqs[0].Body, &body); err != nil {
		t.Fatal(err)
	}
	got := body.Payload.Events
	if len(got) != 2 || got[0].RepeatCount != 2 || got[1].RepeatCount != 1 || got[0].Findings[0].Detector != "secrets.github-pat" {
		t.Errorf("events = %+v", got)
	}
	if reqs[0].Header.Get("X-Device-ID") != "device-1" {
		t.Error("X-Device-ID missing")
	}
}

func TestSendEvents_StripsNUL(t *testing.T) {
	fake := supabasetest.New(t)
	fake.Handle(http.MethodPost, eventsPath, supabasetest.Response{Status: 200, Body: enqueued})
	ev := sampleEvent("c")
	ev.SourceApp.Name = "evil\x00.exe"
	if err := newService(fake).SendEvents(context.Background(), []events.Event{ev}); err != nil {
		t.Fatal(err)
	}
	if body := string(fake.Requests()[0].Body); strings.Contains(body, `\u0000`) {
		t.Errorf("NUL escape sent: %s", body)
	}
}

// A 4xx drops the batch (logged); the rows are deleted, not retried forever.
func TestEventSync_4xxDropsBatch(t *testing.T) {
	fake := supabasetest.New(t)
	fake.Handle(http.MethodPost, eventsPath, supabasetest.Response{Status: 400, Body: `{"code":"22023","message":"bad payload"}`})
	q := newQueue(t)
	dlp.NewQueueSink(q).Emit(sampleEvent("c"))

	if err := dlp.NewEventSync(q, newService(fake)).Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if n := pending(t, q); n != 0 {
		t.Errorf("rejected batch still queued (%d rows)", n)
	}
	if len(fake.Requests()) != 1 {
		t.Errorf("4xx retried: %d requests", len(fake.Requests()))
	}
}

// A 5xx is retried with backoff, then the batch is delivered and deleted.
func TestEventSync_5xxRetries(t *testing.T) {
	fake := supabasetest.New(t)
	fake.Handle(http.MethodPost, eventsPath,
		supabasetest.Response{Status: 503, Body: `{}`},
		supabasetest.Response{Status: 200, Body: enqueued})
	q := newQueue(t)
	dlp.NewQueueSink(q).Emit(sampleEvent("c"))

	if err := dlp.NewEventSync(q, newService(fake)).Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(fake.Requests()) != 2 || pending(t, q) != 0 {
		t.Errorf("requests = %d, rows left = %d; want a retry then delivery", len(fake.Requests()), pending(t, q))
	}
}

// A 401 is returned (for DoWithAuthRetry to recover) and the rows are kept.
func TestEventSync_401KeepsRows(t *testing.T) {
	fake := supabasetest.New(t)
	fake.Handle(http.MethodPost, eventsPath, supabasetest.Response{Status: 200, Body: enqueued})
	fake.ExpireJWT()
	q := newQueue(t)
	dlp.NewQueueSink(q).Emit(sampleEvent("c"))

	err := dlp.NewEventSync(q, newService(fake)).Sync(context.Background())
	if !supabase.IsUnauthorized(err) {
		t.Fatalf("err = %v, want unauthorized", err)
	}
	if n := pending(t, q); n != 1 {
		t.Errorf("rows = %d, want the event kept for after recovery", n)
	}
}

func TestSendEvents_NotEnqueuedKeepsRows(t *testing.T) {
	fake := supabasetest.New(t)
	fake.Handle(http.MethodPost, eventsPath, supabasetest.Response{Status: 200, Body: `{"success":true,"enqueued":false}`})
	q := newQueue(t)
	dlp.NewQueueSink(q).Emit(sampleEvent("c"))
	if err := dlp.NewEventSync(q, newService(fake)).Sync(context.Background()); err == nil {
		t.Fatal("Sync succeeded although nothing was enqueued")
	}
	if n := pending(t, q); n != 1 {
		t.Errorf("rows = %d, want 1 kept", n)
	}
}
