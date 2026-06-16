package services_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/models"
	"sentinelgo/internal/service/services"
)

// TestServicesEnqueue_StripsNUL verifies that NUL bytes embedded in collected
// service fields are stripped before the snapshot is POSTed, so Postgres does not
// reject the payload with a "null character not permitted" error.
func TestServicesEnqueue_StripsNUL(t *testing.T) {
	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"msg_id":1}`))
	}))
	defer server.Close()

	svc := services.NewServicesService()
	svc.SetSupabaseURL(server.URL)

	list := []models.ServiceInfo{
		{
			Name:        "ssh\x00d",
			Source:      "systemd",
			DisplayName: "OpenSSH\x00",
			Status:      "running",
			StartType:   "automatic",
			Description: "Secure shell\x00daemon",
			RunAs:       "root\x00",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := svc.SendByRPC(ctx, "dev-1", list, nil); err != nil {
		t.Fatalf("SendByRPC: %v", err)
	}

	if len(body) == 0 {
		t.Fatal("server captured no request body")
	}
	if !json.Valid(body) {
		t.Fatalf("request body is not valid JSON: %q", body)
	}
	if strings.Contains(string(body), "\\u0000") {
		t.Fatalf("request body still contains an encoded NUL escape: %q", body)
	}
}
