package taskstore

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUpdateToken_Direct(t *testing.T) {
	c := NewClient("http://supabase.test", "anon-key", "old-token")
	c.UpdateToken("new-token")
	if c.accessToken != "new-token" {
		t.Errorf("accessToken = %q, want new-token", c.accessToken)
	}
}

func TestUpdateToken_VerifyViaRequest(t *testing.T) {
	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key", "old-token")
	c.UpdateToken("refreshed-token")

	_, _ = c.GetTasks(context.Background())
	if receivedAuth != "Bearer refreshed-token" {
		t.Errorf("Authorization = %q, want Bearer refreshed-token", receivedAuth)
	}
}

func TestGetTasks_Success(t *testing.T) {
	want := AgentTasksResponse{
		ServerTime: "2024-01-01T00:00:00Z",
		Tasks:      []Task{{ID: "task-1", Name: "Test Task", Status: "assigned"}},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/v1/rpc/agent_get_tasks" {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		if key := r.Header.Get("apikey"); key != "test-key" {
			t.Errorf("apikey = %q, want test-key", key)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-token" {
			t.Errorf("Authorization = %q, want Bearer test-token", auth)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-key", "test-token")
	resp, err := c.GetTasks(context.Background())
	if err != nil {
		t.Fatalf("GetTasks: %v", err)
	}
	if resp == nil {
		t.Fatal("GetTasks returned nil")
		return // Early return to satisfy staticcheck
	}
	if resp.ServerTime != want.ServerTime {
		t.Errorf("ServerTime = %q, want %q", resp.ServerTime, want.ServerTime)
	}
	if len(resp.Tasks) != 1 || resp.Tasks[0].ID != "task-1" {
		t.Errorf("Tasks = %v, want one task with ID task-1", resp.Tasks)
	}
}

func TestGetTasks_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key", "token")
	_, err := c.GetTasks(context.Background())
	if err == nil {
		t.Fatal("expected error on 401, got nil")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("error = %q, want to contain authentication failed", err)
	}
}

func TestGetTasks_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "internal error")
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key", "token")
	_, err := c.GetTasks(context.Background())
	if err == nil {
		t.Fatal("expected error on 500, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %q, want to contain 500", err)
	}
}

func TestGetTasks_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{invalid json}`)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key", "token")
	_, err := c.GetTasks(context.Background())
	if err == nil {
		t.Fatal("expected JSON decode error, got nil")
	}
}

func TestUpdateTask_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key", "token")
	if err := c.UpdateTask(context.Background(), "task-1", "success", ""); err != nil {
		t.Fatalf("UpdateTask: %v", err)
	}
}

func TestUpdateTask_WithNote(t *testing.T) {
	var captured map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key", "token")
	if err := c.UpdateTask(context.Background(), "task-1", "failed", "error message"); err != nil {
		t.Fatalf("UpdateTask: %v", err)
	}
	if captured["p_note"] != "error message" {
		t.Errorf("p_note = %q, want error message", captured["p_note"])
	}
	if captured["p_task_id"] != "task-1" {
		t.Errorf("p_task_id = %q, want task-1", captured["p_task_id"])
	}
}

func TestUpdateTask_NoNote(t *testing.T) {
	var captured map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key", "token")
	if err := c.UpdateTask(context.Background(), "task-1", "success", ""); err != nil {
		t.Fatalf("UpdateTask: %v", err)
	}
	if _, ok := captured["p_note"]; ok {
		t.Error("p_note should not be present when note is empty")
	}
}

func TestUpdateTask_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "server error")
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key", "token")
	err := c.UpdateTask(context.Background(), "task-1", "success", "")
	if err == nil {
		t.Fatal("expected error on 500, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %q, want to contain 500", err)
	}
}
