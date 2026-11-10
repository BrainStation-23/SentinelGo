package logging

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sentinelgo/internal/auditlogs/collector"
	"sentinelgo/internal/config"
	auditlogsvc "sentinelgo/internal/service/auditlog"
	"sentinelgo/internal/store"
)

// Tests for the audit-log ingest fixes: stable batch ids and dedup (#436),
// the retention window (#437) and the upload size cap (#438).

// sentBatch is one upload as the fake server saw it.
type sentBatch struct {
	BatchID string
	UIDs    []string
	Size    int
}

// fakeEnqueue records every upload and answers with respond(callIndex, batch).
type fakeEnqueue struct {
	mu      sync.Mutex
	batches []sentBatch
	respond func(n int, b sentBatch) (status int, body string)
}

func (f *fakeEnqueue) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body struct {
			Payload struct {
				BatchID string                        `json:"batch_id"`
				Logs    []map[string][]map[string]any `json:"logs"`
			} `json:"payload"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("bad upload body: %v", err)
		}
		b := sentBatch{BatchID: body.Payload.BatchID, Size: len(raw)}
		for _, g := range body.Payload.Logs {
			for _, rows := range g {
				for _, row := range rows {
					uid, _ := row["uid"].(string)
					b.UIDs = append(b.UIDs, uid)
				}
			}
		}
		f.mu.Lock()
		n := len(f.batches)
		f.batches = append(f.batches, b)
		f.mu.Unlock()

		status, resp := http.StatusOK, `{"success":true,"queued":true}`
		if f.respond != nil {
			status, resp = f.respond(n, b)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(resp))
	}
}

func (f *fakeEnqueue) sent() []sentBatch {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sentBatch(nil), f.batches...)
}

// newIngestIntegration is a LoggingIntegration whose uploads go to fake.
func newIngestIntegration(t *testing.T, fc collector.Collector, fake *fakeEnqueue) *LoggingIntegration {
	t.Helper()
	srv := httptest.NewServer(fake.handler(t))
	t.Cleanup(srv.Close)

	li := newTestIntegration(t, fc)
	li.cfg = &config.Config{SupabaseURL: srv.URL, DeviceID: "dev", AccessToken: "tok", CurrentVersion: "test",
		LogFlushInterval: config.Duration(5 * time.Minute)}
	li.window = loadWindow(t.TempDir())
	li.uploader = NewUploader(li.cfg, &li.stats)
	li.uploader.window = li.window
	return li
}

func storeEntries(t *testing.T, li *LoggingIntegration, entries []collector.RawLogEntry) {
	t.Helper()
	if err := li.store.Insert(li.parser.Parse(entries, li.parserConfig())); err != nil {
		t.Fatalf("Insert: %v", err)
	}
}

func pendingCount(t *testing.T, st *store.AuditLogStore) int {
	t.Helper()
	rows, err := st.GetPending(0)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	return len(rows)
}

// The server commits a batch, but the agent sees a 500 and retries: the retry
// carries the same batch_id and row uids, and when the server answers
// duplicate: true the rows are removed from the queue (#436).
func TestUploadFromStore_RetrySendsSameBatchID(t *testing.T) {
	fake := &fakeEnqueue{respond: func(n int, _ sentBatch) (int, string) {
		if n == 0 {
			return http.StatusInternalServerError, `{"message":"timeout after commit"}`
		}
		return http.StatusOK, `{"success":true,"queued":false,"duplicate":true}`
	}}
	li := newIngestIntegration(t, &fakeCollector{}, fake)
	storeEntries(t, li, makeBatch("e", 5, time.Now()))

	n, err := li.uploader.UploadFromStore(context.Background(), li.store)
	if err != nil || n != 5 {
		t.Fatalf("UploadFromStore = %d, %v; want 5, nil", n, err)
	}
	sent := fake.sent()
	if len(sent) != 2 {
		t.Fatalf("server saw %d uploads, want 2 (first + retry)", len(sent))
	}
	if sent[0].BatchID == "" || sent[0].BatchID != sent[1].BatchID {
		t.Errorf("batch ids = %q, %q; want the same non-empty id", sent[0].BatchID, sent[1].BatchID)
	}
	if strings.Join(sent[0].UIDs, ",") != strings.Join(sent[1].UIDs, ",") || len(sent[0].UIDs) != 5 || sent[0].UIDs[0] == "" {
		t.Errorf("uids differ or are missing: %v vs %v", sent[0].UIDs, sent[1].UIDs)
	}
	if c := pendingCount(t, li.store); c != 0 {
		t.Errorf("%d rows still queued after duplicate: true, want 0", c)
	}
}

// A chunk that fails keeps its batch id in the queue: the next cycle (even
// after a restart) resends exactly that chunk, under the same id, and nothing
// that was already confirmed (#436).
func TestUploadFromStore_FailedChunkResentAlone(t *testing.T) {
	var failSecond atomic.Bool
	failSecond.Store(true)
	// The first cycle ends when the second chunk fails (a 5xx is otherwise
	// retried until the context ends), so the test doesn't depend on timing.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := &fakeEnqueue{}
	fake.respond = func(n int, _ sentBatch) (int, string) {
		if n == 1 && failSecond.Load() {
			cancel()
			return http.StatusBadGateway, `{}`
		}
		return http.StatusOK, `{"success":true}`
	}
	li := newIngestIntegration(t, &fakeCollector{}, fake)
	// ~2 KB per row: 200 rows need two chunks under the 256 KB cap.
	entries := makeBatch("big", 200, time.Now())
	for i := range entries {
		entries[i].RawMessage = strings.Repeat("x", 2000) + entries[i].RawMessage
	}
	storeEntries(t, li, entries)

	_, err := li.uploader.UploadFromStore(ctx, li.store)
	if err == nil {
		t.Fatal("want an error from the failing chunk")
	}
	first := fake.sent()
	if len(first) < 2 {
		t.Fatalf("server saw %d uploads, want at least 2", len(first))
	}
	confirmed, failed := first[0], first[1]
	left := pendingCount(t, li.store)
	if left != len(failed.UIDs) || left == 0 || left == 200 {
		t.Fatalf("%d rows queued, want only the failed chunk's %d", left, len(failed.UIDs))
	}

	failSecond.Store(false)
	before := len(fake.sent())
	if _, err := li.uploader.UploadFromStore(context.Background(), li.store); err != nil {
		t.Fatalf("second cycle: %v", err)
	}
	next := fake.sent()[before:]
	if len(next) == 0 || next[0].BatchID != failed.BatchID || strings.Join(next[0].UIDs, ",") != strings.Join(failed.UIDs, ",") {
		t.Fatalf("next cycle sent %+v first, want the failed chunk %s again", next, failed.BatchID)
	}
	for _, b := range next {
		if b.BatchID == confirmed.BatchID {
			t.Error("the confirmed chunk was sent again")
		}
	}
	if c := pendingCount(t, li.store); c != 0 {
		t.Errorf("%d rows still queued, want 0", c)
	}
}

// No upload body is over 256 KB, however much is queued (#438).
func TestUploadFromStore_BodiesStayUnderCap(t *testing.T) {
	fake := &fakeEnqueue{}
	li := newIngestIntegration(t, &fakeCollector{}, fake)
	entries := makeBatch("big", 1200, time.Now())
	for i := range entries {
		entries[i].Metadata["blob"] = strings.Repeat("y", 9000) // near the per-row cap
	}
	storeEntries(t, li, entries)

	n, err := li.uploader.UploadFromStore(context.Background(), li.store)
	if err != nil || n != 1200 {
		t.Fatalf("UploadFromStore = %d, %v; want 1200, nil", n, err)
	}
	for i, b := range fake.sent() {
		if b.Size > maxPayloadBytes {
			t.Errorf("upload %d is %d bytes, over %d", i, b.Size, maxPayloadBytes)
		}
	}
}

// An event delivered by the real-time subscription and then returned again by
// the next poll is uploaded once (#436).
func TestRealtimeThenPoll_UploadedOnce(t *testing.T) {
	ev := makeBatch("same", 1, time.Now().Add(-time.Minute))
	fake := &fakeEnqueue{}
	fc := &fakeCollector{batches: [][]collector.RawLogEntry{ev}}
	li := newIngestIntegration(t, fc, fake)

	storeEntries(t, li, ev) // what subscriptionLoop does
	if _, err := li.uploader.UploadFromStore(context.Background(), li.store); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if err := li.runCollection(context.Background()); err != nil { // the poll returns it again
		t.Fatalf("runCollection: %v", err)
	}
	if _, err := li.uploader.UploadFromStore(context.Background(), li.store); err != nil {
		t.Fatalf("upload: %v", err)
	}
	var rows int
	for _, b := range fake.sent() {
		rows += len(b.UIDs)
	}
	if rows != 1 {
		t.Errorf("the event was uploaded %d times, want 1", rows)
	}
}

// With retention 3 days, a backlog spanning 10 days queues only the last 3
// days; rows more than a day in the future are dropped too, and both are
// counted (#437).
func TestRunCollection_KeepsOnlyRetentionWindow(t *testing.T) {
	now := time.Now()
	var batch []collector.RawLogEntry
	for d := 0; d < 10; d++ {
		batch = append(batch, makeBatch("day"+string(rune('a'+d)), 10, now.Add(-time.Duration(d)*24*time.Hour-time.Hour))...)
	}
	batch = append(batch, makeBatch("future", 5, now.Add(3*24*time.Hour))...)
	batch = append(batch, makeBatch("soon", 5, now.Add(time.Hour))...) // clock skew: kept
	li := newTestIntegration(t, &fakeCollector{batches: [][]collector.RawLogEntry{batch}})

	if err := li.runCollection(context.Background()); err != nil {
		t.Fatalf("runCollection: %v", err)
	}
	// Days 0, 1 and 2 (each an hour into the day) are inside 3 days.
	if got, want := pendingCount(t, li.store), 30+5; got != want {
		t.Errorf("queued %d rows, want %d", got, want)
	}
	if got, want := li.GetStatistics().DroppedOutOfWindow, int64(70+5); got != want {
		t.Errorf("DroppedOutOfWindow = %d, want %d", got, want)
	}
}

// The server's window from an enqueue response replaces the default, is
// persisted, and drives the collectors' first-run lookback (#437).
func TestWindow_UpdatedFromResponse(t *testing.T) {
	dir := t.TempDir()
	fake := &fakeEnqueue{respond: func(int, sentBatch) (int, string) {
		return http.StatusOK, `{"success":true,"audit_logs":{"retention_days":5,` +
			`"accept_after":"2000-01-01T00:00:00Z","accept_before":"2000-01-02T00:00:00Z","max_event_data_bytes":4000}}`
	}}
	li := newIngestIntegration(t, &fakeCollector{}, fake)
	li.window = loadWindow(dir)
	li.uploader.window = li.window
	storeEntries(t, li, makeBatch("w", 1, time.Now()))

	if li.window.retention() != 3*24*time.Hour {
		t.Fatalf("default retention = %s, want 3 days", li.window.retention())
	}
	if _, err := li.uploader.UploadFromStore(context.Background(), li.store); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if li.window.retention() != 5*24*time.Hour || li.window.maxEventDataBytes() != 4000 {
		t.Errorf("window = %s / %d, want 5 days / 4000", li.window.retention(), li.window.maxEventDataBytes())
	}
	// Stale server bounds (from 2000) don't narrow today's window.
	after, before := li.window.bounds()
	if time.Since(after) < 5*24*time.Hour-time.Minute || time.Until(before) < 23*time.Hour {
		t.Errorf("bounds = %s .. %s, want now-5d .. now+1d", after, before)
	}

	reloaded := loadWindow(dir)
	if reloaded.retention() != 5*24*time.Hour || reloaded.maxEventDataBytes() != 4000 {
		t.Errorf("persisted window = %s / %d, want 5 days / 4000", reloaded.retention(), reloaded.maxEventDataBytes())
	}
}

// Fresh server bounds narrow the window; out-of-range retention is ignored.
func TestWindow_Bounds(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	w := &auditWindow{path: filepath.Join(t.TempDir(), windowFile), now: func() time.Time { return now },
		st: windowState{RetentionDays: 3}}
	w.update(&auditlogsvc.ServerWindow{RetentionDays: 99, AcceptAfter: now.Add(-24 * time.Hour), AcceptBefore: now.Add(time.Hour)})
	if w.retention() != 3*24*time.Hour {
		t.Errorf("retention = %s, want 3 days (99 is out of range)", w.retention())
	}
	after, before := w.bounds()
	if !after.Equal(now.Add(-24*time.Hour)) || !before.Equal(now.Add(time.Hour)) {
		t.Errorf("bounds = %s .. %s, want the server's", after, before)
	}
}

// Collectors that support it start at the window, not at the log's start.
func TestNewLoggingIntegration_SetsCollectorLookback(t *testing.T) {
	cfg := &config.Config{DeviceID: "d", Path: filepath.Join(t.TempDir(), "config.json"),
		LogFlushInterval: config.Duration(time.Minute)}
	li, err := NewLoggingIntegration(cfg)
	if err != nil {
		t.Fatalf("NewLoggingIntegration: %v", err)
	}
	t.Cleanup(func() { _ = li.store.Close() })
	if _, ok := li.collector.(collector.StartBounded); !ok {
		t.Skip("this OS's collector has no first-run bound")
	}
	if li.uploader.window != li.window || li.window == nil {
		t.Error("the uploader doesn't update the integration's window")
	}
}
