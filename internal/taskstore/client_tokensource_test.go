package taskstore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"sentinelgo/internal/supabase"
)

// The production client reads the token per request, so a refreshed token is
// used immediately (taskstore used to capture the token once at construction
// and keep sending it after it expired).
func TestTokenSource_ReadPerRequest(t *testing.T) {
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = w.Write([]byte(`{"tasks":[]}`))
	}))
	defer srv.Close()

	current := "token-1"
	c := NewClientWithTokenSource(srv.URL, "anon", func() string { return current })
	if _, err := c.GetTasks(context.Background()); err != nil {
		t.Fatal(err)
	}
	current = "token-2"
	if err := c.UpdateTask(context.Background(), "t1", "success", ""); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if strings.Join(got, ",") != "Bearer token-1,Bearer token-2" {
		t.Errorf("Authorization headers = %v, want the current token on each request", got)
	}
}

func TestGetTasks_401IsClassifiable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"PGRST301","message":"JWT expired"}`))
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL, "anon", "expired").GetTasks(context.Background())
	if !supabase.IsUnauthorized(err) {
		t.Fatalf("err = %v, want a typed 401 the poller can recover from", err)
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("err = %v, want it to keep the 'authentication failed' prefix", err)
	}
}
