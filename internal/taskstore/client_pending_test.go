package taskstore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// pendingServer answers agent_has_pending_tasks with body, or 404 PGRST202
// when the backend doesn't have it (sentinel-ops before #472).
func pendingServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/rpc/agent_has_pending_tasks") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestHasPendingTasks(t *testing.T) {
	for _, tc := range []struct {
		body string
		want bool
	}{
		{`{"pending": true}`, true},
		{`{"pending": false}`, false},
	} {
		c := NewClient(pendingServer(t, http.StatusOK, tc.body).URL, "key", "token")
		got, err := c.HasPendingTasks(context.Background())
		if err != nil || got != tc.want {
			t.Errorf("%s: got %v, %v; want %v", tc.body, got, err, tc.want)
		}
	}
}

func TestHasPendingTasks_OlderServer(t *testing.T) {
	srv := pendingServer(t, http.StatusNotFound,
		`{"code":"PGRST202","message":"Could not find the function public.agent_has_pending_tasks without parameters in the schema cache"}`)
	_, err := NewClient(srv.URL, "key", "token").HasPendingTasks(context.Background())
	if !errors.Is(err, ErrNoPendingCheck) {
		t.Errorf("err = %v, want ErrNoPendingCheck", err)
	}
}

func TestHasPendingTasks_OtherErrors(t *testing.T) {
	srv := pendingServer(t, http.StatusInternalServerError, `{"message":"boom"}`)
	_, err := NewClient(srv.URL, "key", "token").HasPendingTasks(context.Background())
	if err == nil || errors.Is(err, ErrNoPendingCheck) {
		t.Errorf("err = %v, want a plain error", err)
	}
}
