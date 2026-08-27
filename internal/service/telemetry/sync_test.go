package telemetry

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tel "sentinelgo/internal/telemetry"

	"sentinelgo/internal/config"
	"sentinelgo/internal/store"
)

// newTestService builds a telemetry service backed by temp databases and
// pointed at a test HTTP server.
func newTestService(t *testing.T, handler http.HandlerFunc) (*Service, *httptest.Server) {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	cfg := &config.Config{
		Path:        filepath.Join(t.TempDir(), "config.json"),
		DeviceID:    "dev-test",
		SupabaseURL: srv.URL,
		SupabaseKey: "anon-key",
		AccessToken: "jwt-token",
		AgentID:     "agent-test",
		AgentSecret: "secret",
	}

	svc, err := New(cfg, tel.NewCollectorSet())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc, srv
}

// enqueueTestMessage puts one message on the queue.
func enqueueTestMessage(t *testing.T, svc *Service, section, payload string) {
	t.Helper()
	if _, err := svc.queueStore.Enqueue(store.OutboundMessage{
		SnapshotID: "snap-1",
		Section:    section,
		Class:      "inventory",
		Priority:   50,
		BatchCount: 1,
		Payload:    payload,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
}

// seedSectionState records a collected section so MarkUploaded has a row to
// advance. Reconcile timestamps only exist for sections that were collected.
func seedSectionState(t *testing.T, svc *Service, section string) {
	t.Helper()
	if err := svc.stateStore.MarkCollected(section, 1, "hash-1", 1, "success", time.Now().UTC()); err != nil {
		t.Fatalf("MarkCollected: %v", err)
	}
}

// ── success path ─────────────────────────────────────────────────────────────

// TestFlushDeletesOnlyAfterAcknowledgement verifies the core ordering
// guarantee: a queue row disappears only once the backend has accepted it, and
// the section reconcile clock advances only then.
func TestFlushDeletesOnlyAfterAcknowledgement(t *testing.T) {
	var calls atomic.Int32
	svc, _ := newTestService(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if got := r.Header.Get("Authorization"); got != "Bearer jwt-token" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("apikey"); got != "anon-key" {
			t.Errorf("apikey = %q", got)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"enqueued":true,"msg_id":7,"queue":"telemetry"}`))
	})

	seedSectionState(t, svc, "identity")
	enqueueTestMessage(t, svc, "identity", `{"payload":{"sections":["identity"]}}`)

	before, err := svc.stateStore.Get("identity")
	if err != nil || before == nil {
		t.Fatalf("seed state: %v", err)
	}
	if !before.LastReconciledAt.IsZero() {
		t.Fatal("reconcile clock must start unset")
	}

	res, err := svc.Flush(context.Background())
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if res.Delivered != 1 {
		t.Errorf("delivered = %d, want 1", res.Delivered)
	}
	if calls.Load() != 1 {
		t.Errorf("HTTP calls = %d, want 1", calls.Load())
	}

	depth, _ := svc.queueStore.Depth()
	if depth != 0 {
		t.Errorf("queue depth = %d, want 0 after acknowledgement", depth)
	}

	after, _ := svc.stateStore.Get("identity")
	if after.LastReconciledAt.IsZero() {
		t.Error("reconcile clock must advance after a confirmed delivery")
	}
}

// TestFlushDrainsMultipleMessages checks the loop covers a backlog.
func TestFlushDrainsMultipleMessages(t *testing.T) {
	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true}`))
	})

	seedSectionState(t, svc, "identity")
	for i := 0; i < 12; i++ {
		enqueueTestMessage(t, svc, "identity", `{"payload":{}}`)
	}

	res, err := svc.Flush(context.Background())
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if res.Delivered != 12 {
		t.Errorf("delivered = %d, want 12", res.Delivered)
	}
	if depth, _ := svc.queueStore.Depth(); depth != 0 {
		t.Errorf("queue depth = %d, want 0", depth)
	}
}

// ── rejection path: the anti-silent-drop guarantee ───────────────────────────

// TestFlushRetainsRejectedPayload is the most important test here.
//
// rpcutil.WithEnqueueRetry logs a non-auth 4xx and returns nil — its
// "server rejected the payload, dropping" behaviour. If the sender trusted that
// nil, a rejected telemetry message would be deleted and lost without trace.
// The sender inspects the recorded status instead, so the row is retained,
// counted and logged.
func TestFlushRetainsRejectedPayload(t *testing.T) {
	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"unknown column"}`))
	})

	seedSectionState(t, svc, "identity")
	enqueueTestMessage(t, svc, "identity", `{"payload":{}}`)

	res, err := svc.Flush(context.Background())
	if err != nil {
		t.Fatalf("Flush should not fail on a rejection: %v", err)
	}

	if res.Rejected != 1 {
		t.Errorf("rejected = %d, want 1", res.Rejected)
	}
	if res.Delivered != 0 {
		t.Errorf("delivered = %d, want 0", res.Delivered)
	}

	depth, _ := svc.queueStore.Depth()
	if depth != 1 {
		t.Fatalf("queue depth = %d, want 1 — a rejected message must NOT be dropped", depth)
	}

	pending, _ := svc.queueStore.GetPending(10)
	if pending[0].Attempts != 1 {
		t.Errorf("attempts = %d, want 1", pending[0].Attempts)
	}

	state, _ := svc.stateStore.Get("identity")
	if !state.LastReconciledAt.IsZero() {
		t.Error("reconcile clock must NOT advance for a rejected payload")
	}
}

// TestFlushDoesNotLogRawResponseBody is the regression proof for the
// telemetry security hardening: a rejected message's backend response body
// must never reach any log line — not the [telemetry] backend REJECTED line
// from recordRejection, not the shared rpcutil enqueue-retry policy's own
// "server rejected payload" line, and not any error surfaced further up the
// call chain. A Postgres/PostgREST rejection response routinely echoes back
// the offending submitted value, so the response body here deliberately
// contains a marker that looks exactly like that — and the test fails if the
// marker appears anywhere in the captured log output.
func TestFlushDoesNotLogRawResponseBody(t *testing.T) {
	const marker = "tenant_id=87654321-dcba-4321-dcba-fedcba987654-SHOULD-NEVER-BE-LOGGED"

	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"constraint violation","detail":"Key (` + marker + `) already exists."}`))
	})

	seedSectionState(t, svc, "directory")
	enqueueTestMessage(t, svc, "directory", `{"payload":{}}`)

	var captured bytes.Buffer
	prevOutput := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&captured)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOutput)
		log.SetFlags(prevFlags)
	})

	res, err := svc.Flush(context.Background())
	if err != nil {
		t.Fatalf("Flush should not fail on a rejection: %v", err)
	}
	if res.Rejected != 1 {
		t.Fatalf("rejected = %d, want 1 (fixture didn't exercise the rejection path)", res.Rejected)
	}

	logged := captured.String()
	if strings.Contains(logged, marker) {
		t.Errorf("backend response body leaked into logs:\n%s", logged)
	}
	if !strings.Contains(logged, "REJECTED") {
		t.Error("expected a REJECTED log line to be present (with status, not body)")
	}
	if !strings.Contains(logged, "422") {
		t.Error("expected the log to carry the HTTP status code even without the body")
	}
}

// TestExhaustedMessageIsDeadLettered verifies what happens to a message the
// backend permanently refuses.
//
// It must stop consuming requests, leave the delivery path so it cannot starve
// the queue behind it, and still be retained locally for inspection — deleting
// it would be the silent data loss this sender exists to prevent.
func TestExhaustedMessageIsDeadLettered(t *testing.T) {
	var calls atomic.Int32
	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnprocessableEntity)
	})

	seedSectionState(t, svc, "identity")
	enqueueTestMessage(t, svc, "identity", `{"payload":{}}`)

	for i := 0; i < maxDeliveryAttempts+3; i++ {
		if _, err := svc.Flush(context.Background()); err != nil {
			t.Fatalf("Flush %d: %v", i, err)
		}
	}

	if got := int(calls.Load()); got != maxDeliveryAttempts {
		t.Errorf("HTTP calls = %d, want %d (retries must stop at the cap)", got, maxDeliveryAttempts)
	}

	// Out of the delivery path...
	depth, _ := svc.QueueDepth()
	if depth != 0 {
		t.Errorf("deliverable depth = %d, want 0 once dead-lettered", depth)
	}

	// ...but retained.
	dead, err := svc.DeadLetterDepth()
	if err != nil {
		t.Fatalf("DeadLetterDepth: %v", err)
	}
	if dead != 1 {
		t.Fatalf("dead-letter depth = %d, want 1 — the message must be retained, not deleted", dead)
	}

	msgs, err := svc.DeadLettered(10)
	if err != nil {
		t.Fatalf("DeadLettered: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected one dead-lettered message, got %d", len(msgs))
	}
	if !msgs[0].DeadLettered {
		t.Error("message should be flagged dead-lettered")
	}
	if msgs[0].Payload == "" {
		t.Error("the payload must be preserved for inspection")
	}
	if msgs[0].Attempts != maxDeliveryAttempts {
		t.Errorf("attempts = %d, want %d", msgs[0].Attempts, maxDeliveryAttempts)
	}

	// The section reconcile clock must never have advanced.
	state, _ := svc.stateStore.Get("identity")
	if !state.LastReconciledAt.IsZero() {
		t.Error("reconcile clock must not advance for an undelivered message")
	}
}

// TestFlushReportsDeadLetterTransition checks the flush result surfaces the
// transition, so it is observable rather than only visible in logs.
func TestFlushReportsDeadLetterTransition(t *testing.T) {
	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})

	seedSectionState(t, svc, "identity")
	enqueueTestMessage(t, svc, "identity", `{"payload":{}}`)

	var lastResult FlushResult
	for i := 0; i < maxDeliveryAttempts; i++ {
		res, err := svc.Flush(context.Background())
		if err != nil {
			t.Fatalf("Flush %d: %v", i, err)
		}
		lastResult = res
	}

	if lastResult.DeadLettered != 1 {
		t.Errorf("DeadLettered = %d, want 1 on the flush that exhausts attempts", lastResult.DeadLettered)
	}
	if lastResult.DeadLetterDepth != 1 {
		t.Errorf("DeadLetterDepth = %d, want 1", lastResult.DeadLetterDepth)
	}
	if lastResult.Remaining != 0 {
		t.Errorf("Remaining = %d, want 0 — dead-lettered rows are not deliverable backlog", lastResult.Remaining)
	}
}

// ── transient and auth paths ─────────────────────────────────────────────────

// TestFlushRetainsOnServerError verifies a 5xx leaves everything queued.
func TestFlushRetainsOnServerError(t *testing.T) {
	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	seedSectionState(t, svc, "identity")
	enqueueTestMessage(t, svc, "identity", `{"payload":{}}`)

	// A short deadline so the retry policy gives up quickly rather than backing
	// off for the full RPC timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res, err := svc.Flush(ctx)
	if err == nil {
		t.Error("a transient failure should surface as an error, not be swallowed")
	}
	if res.Delivered != 0 {
		t.Errorf("delivered = %d, want 0", res.Delivered)
	}
	if depth, _ := svc.queueStore.Depth(); depth != 1 {
		t.Errorf("queue depth = %d, want 1 — nothing may be lost on a 5xx", depth)
	}

	state, _ := svc.stateStore.Get("identity")
	if !state.LastReconciledAt.IsZero() {
		t.Error("reconcile clock must not advance when delivery failed")
	}
}

// TestFlushPropagatesUnauthorized verifies a 401 surfaces so the caller can
// recover the session, and leaves the message queued.
func TestFlushPropagatesUnauthorized(t *testing.T) {
	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	seedSectionState(t, svc, "identity")
	enqueueTestMessage(t, svc, "identity", `{"payload":{}}`)

	res, err := svc.Flush(context.Background())
	if err == nil {
		t.Fatal("a 401 must propagate so the session can be recovered")
	}
	if res.Delivered != 0 {
		t.Errorf("delivered = %d, want 0", res.Delivered)
	}
	if depth, _ := svc.queueStore.Depth(); depth != 1 {
		t.Errorf("queue depth = %d, want 1", depth)
	}
}

// ── retry idempotency ────────────────────────────────────────────────────────

// TestRetrySendsIdenticalBytes verifies a redelivery replays the stored payload
// verbatim, so snapshot_id, batch_index and batch_count are unchanged and the
// backend never sees two logical snapshots for one collection.
func TestRetrySendsIdenticalBytes(t *testing.T) {
	var bodies [][]byte
	var fail atomic.Bool
	fail.Store(true)

	svc, _ := newTestService(t, func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		bodies = append(bodies, buf)

		if fail.Load() {
			w.WriteHeader(http.StatusConflict) // 4xx: retained, retried next flush
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	seedSectionState(t, svc, "processes")
	payload := `{"payload":{"chunk":{"snapshot_id":"abc123","batch_index":0,"batch_count":2,"total_items":900}}}`
	enqueueTestMessage(t, svc, "processes", payload)

	if _, err := svc.Flush(context.Background()); err != nil {
		t.Fatalf("first flush: %v", err)
	}
	fail.Store(false)
	if _, err := svc.Flush(context.Background()); err != nil {
		t.Fatalf("second flush: %v", err)
	}

	if len(bodies) != 2 {
		t.Fatalf("expected two attempts, got %d", len(bodies))
	}
	if string(bodies[0]) != string(bodies[1]) {
		t.Fatal("retry sent different bytes; snapshot identity must be stable across retries")
	}
	if string(bodies[0]) != payload {
		t.Errorf("payload was altered in transit:\n got %s\nwant %s", bodies[0], payload)
	}
}

// ── reset scope ──────────────────────────────────────────────────────────────

// TestResetStateOnlyTouchesTelemetry verifies the blast radius of a reset.
//
// It must clear telemetry section state and the outbound queue and nothing
// else — credentials, device identity and agent registration are untouched, so
// the command is safe to run on a live agent.
func TestResetStateOnlyTouchesTelemetry(t *testing.T) {
	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	seedSectionState(t, svc, "identity")
	seedSectionState(t, svc, "os")
	for i := 0; i < 5; i++ {
		enqueueTestMessage(t, svc, "identity", `{"payload":{}}`)
	}

	// Snapshot the identity-bearing config values.
	deviceID := svc.cfg.DeviceID
	agentID := svc.cfg.AgentID
	agentSecret := svc.cfg.AgentSecret
	accessToken := svc.cfg.GetAccessToken()
	supabaseURL := svc.cfg.SupabaseURL

	if err := svc.ResetState(); err != nil {
		t.Fatalf("ResetState: %v", err)
	}

	all, err := svc.stateStore.GetAll()
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	if len(all) != 0 {
		t.Errorf("section state = %d entries, want 0", len(all))
	}
	if depth, _ := svc.queueStore.Depth(); depth != 0 {
		t.Errorf("queue depth = %d, want 0", depth)
	}

	if svc.cfg.DeviceID != deviceID {
		t.Error("reset must not change device_id")
	}
	if svc.cfg.AgentID != agentID {
		t.Error("reset must not change agent_id")
	}
	if svc.cfg.AgentSecret != agentSecret {
		t.Error("reset must not change agent_secret")
	}
	if svc.cfg.GetAccessToken() != accessToken {
		t.Error("reset must not change the access token")
	}
	if svc.cfg.SupabaseURL != supabaseURL {
		t.Error("reset must not change the backend URL")
	}
}

// TestResetClearsFullQueueNotJustAPage guards against the queue clear being
// capped by a pagination limit, which would silently leave rows behind.
func TestResetClearsFullQueueNotJustAPage(t *testing.T) {
	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < 250; i++ {
		enqueueTestMessage(t, svc, "processes", `{"payload":{}}`)
	}
	if depth, _ := svc.queueStore.Depth(); depth != 250 {
		t.Fatalf("setup: queue depth = %d, want 250", depth)
	}

	if err := svc.ResetState(); err != nil {
		t.Fatalf("ResetState: %v", err)
	}
	if depth, _ := svc.queueStore.Depth(); depth != 0 {
		t.Fatalf("queue depth = %d, want 0 — the whole queue must be cleared", depth)
	}
}

// TestFlushWithoutBackendURL checks the misconfiguration path.
func TestFlushWithoutBackendURL(t *testing.T) {
	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	svc.cfg.SupabaseURL = ""

	if _, err := svc.Flush(context.Background()); err == nil {
		t.Fatal("expected an error when the backend URL is unset")
	}
}

// TestFlushEmptyQueueIsNoOp checks the common idle case.
func TestFlushEmptyQueueIsNoOp(t *testing.T) {
	var calls atomic.Int32
	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	res, err := svc.Flush(context.Background())
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if res.Delivered != 0 || calls.Load() != 0 {
		t.Errorf("an empty queue must not produce requests: delivered=%d calls=%d", res.Delivered, calls.Load())
	}
}

// ── transient-failure budget ─────────────────────────────────────────────────

// TestBackendOutageDoesNotStrandAMessage is the "retained for retry" guarantee
// for transient failures.
//
// The per-message attempt budget exists to bound REJECTIONS — a payload the
// backend keeps refusing is a defect to investigate, so it is dead-lettered and
// retained rather than retried forever. A backend outage is a different thing
// entirely: the payload is fine and the only correct action is to try again
// later. If an outage consumes the same budget, the oldest queued messages pass
// the threshold during the outage and are then skipped by the poison safety net
// in deliverBatch — never delivered, never dead-lettered, and visible only as a
// Poisoned counter. That is silent loss of collected telemetry caused by
// nothing worse than the backend being down for a while.
func TestBackendOutageDoesNotStrandAMessage(t *testing.T) {
	var outage atomic.Bool
	outage.Store(true)

	svc, _ := newTestService(t, func(w http.ResponseWriter, _ *http.Request) {
		if outage.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	seedSectionState(t, svc, "identity")
	enqueueTestMessage(t, svc, "identity", `{"payload":{}}`)

	// Ride out an outage longer than the attempt budget. Each flush gets a short
	// deadline so the backoff inside the retry policy does not stall the test.
	for i := 0; i < maxDeliveryAttempts+2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		_, err := svc.Flush(ctx)
		cancel()
		if err == nil {
			t.Fatalf("flush %d during outage: expected a transient error", i)
		}
		if depth, _ := svc.queueStore.Depth(); depth != 1 {
			t.Fatalf("flush %d during outage: queue depth = %d, want 1", i, depth)
		}
		if dead, _ := svc.queueStore.DeadLetterDepth(); dead != 0 {
			t.Fatalf("flush %d during outage: %d message(s) dead-lettered — an "+
				"unreachable backend is not a rejected payload", i, dead)
		}
	}

	// The backend comes back.
	outage.Store(false)

	res, err := svc.Flush(context.Background())
	if err != nil {
		t.Fatalf("flush after recovery: %v", err)
	}
	if res.Poisoned != 0 {
		t.Errorf("Poisoned = %d, want 0 — an outage must not poison a valid message", res.Poisoned)
	}
	if res.Delivered != 1 {
		t.Fatalf("delivered = %d, want 1 — the message was stranded by the outage "+
			"instead of being retried once the backend recovered", res.Delivered)
	}
	if depth, _ := svc.queueStore.Depth(); depth != 0 {
		t.Errorf("queue depth = %d, want 0 after successful delivery", depth)
	}
}
