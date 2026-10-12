package taskstore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// resultServer records each agent_update_task body. When oldBackend is set it
// answers PGRST202 to any call that carries p_result, as a backend without
// sentinel-ops#49 does.
func resultServer(t *testing.T, oldBackend bool) (*httptest.Server, func() []map[string]interface{}) {
	t.Helper()
	var mu sync.Mutex
	var calls []map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		mu.Lock()
		calls = append(calls, body)
		mu.Unlock()
		if _, has := body["p_result"]; has && oldBackend {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":"PGRST202","message":"Could not find the function public.agent_update_task(p_note, p_result, p_status, p_task_id) in the schema cache"}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []map[string]interface{} {
		mu.Lock()
		defer mu.Unlock()
		return append([]map[string]interface{}{}, calls...)
	}
}

func TestUpdateTaskWithResult_SendsResult(t *testing.T) {
	srv, calls := resultServer(t, false)
	c := NewClient(srv.URL, "key", "token")
	result := map[string]interface{}{"exit_code": 3010, "reboot_required": true}
	if err := c.UpdateTaskWithResult(context.Background(), "t1", "success", "ok", result); err != nil {
		t.Fatalf("UpdateTaskWithResult: %v", err)
	}
	got := calls()
	if len(got) != 1 {
		t.Fatalf("calls = %d, want 1", len(got))
	}
	r, ok := got[0]["p_result"].(map[string]interface{})
	if !ok || r["exit_code"] != float64(3010) || r["reboot_required"] != true {
		t.Errorf("p_result = %v", got[0]["p_result"])
	}
}

func TestUpdateTaskWithResult_NilResultOmitted(t *testing.T) {
	srv, calls := resultServer(t, false)
	c := NewClient(srv.URL, "key", "token")
	if err := c.UpdateTask(context.Background(), "t1", "success", "ok"); err != nil {
		t.Fatalf("UpdateTask: %v", err)
	}
	if _, has := calls()[0]["p_result"]; has {
		t.Error("p_result sent without a result")
	}
}

// TestUpdateTaskWithResult_OldBackend: PGRST202 retries once without
// p_result, and later calls skip it.
func TestUpdateTaskWithResult_OldBackend(t *testing.T) {
	srv, calls := resultServer(t, true)
	c := NewClient(srv.URL, "key", "token")
	result := map[string]interface{}{"exit_code": 1}

	if err := c.UpdateTaskWithResult(context.Background(), "t1", "failed", "boom", result); err != nil {
		t.Fatalf("first update: %v", err)
	}
	got := calls()
	if len(got) != 2 {
		t.Fatalf("calls = %d, want 2 (with p_result, then without)", len(got))
	}
	if _, has := got[1]["p_result"]; has || got[1]["p_note"] != "boom" || got[1]["p_status"] != "failed" {
		t.Errorf("retry body = %v, want the same update without p_result", got[1])
	}

	if err := c.UpdateTaskWithResult(context.Background(), "t2", "success", "", result); err != nil {
		t.Fatalf("second update: %v", err)
	}
	got = calls()
	if len(got) != 3 {
		t.Fatalf("calls = %d, want 3 (the second update goes out once, without p_result)", len(got))
	}
	if _, has := got[2]["p_result"]; has {
		t.Error("p_result sent again after the backend showed it has none")
	}
}

// TestUpdateTaskWithResult_OtherNotFoundNotRetried: a 404 that isn't
// PGRST202 is an ordinary failure.
func TestUpdateTaskWithResult_OtherNotFoundNotRetried(t *testing.T) {
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n++
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"P0002","message":"task not found"}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "key", "token")
	if err := c.UpdateTaskWithResult(context.Background(), "t1", "success", "", map[string]interface{}{"exit_code": 0}); err == nil {
		t.Fatal("want an error")
	}
	if n != 1 {
		t.Errorf("calls = %d, want 1", n)
	}
	if c.noResultUntil.Load() != 0 {
		t.Error("a non-PGRST202 404 disabled p_result")
	}
}

// TestUpdateTaskWithResult_RechecksAfterInterval: once the recheck interval
// has passed, p_result is tried again, so a backend upgrade is picked up
// without restarting the agent.
func TestUpdateTaskWithResult_RechecksAfterInterval(t *testing.T) {
	srv, calls := resultServer(t, false)
	c := NewClient(srv.URL, "key", "token")
	result := map[string]interface{}{"exit_code": 0}

	c.noResultUntil.Store(time.Now().Add(time.Hour).UnixNano())
	if err := c.UpdateTaskWithResult(context.Background(), "t1", "success", "", result); err != nil {
		t.Fatal(err)
	}
	c.noResultUntil.Store(time.Now().Add(-time.Second).UnixNano())
	if err := c.UpdateTaskWithResult(context.Background(), "t2", "success", "", result); err != nil {
		t.Fatal(err)
	}
	got := calls()
	if _, has := got[0]["p_result"]; has {
		t.Error("p_result sent inside the recheck interval")
	}
	if _, has := got[1]["p_result"]; !has {
		t.Error("p_result not retried after the recheck interval")
	}
}
