package software_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/service/software"
)

// assertNoNUL fails the test unless body is valid JSON with no encoded NUL escape.
func assertNoNUL(t *testing.T, body []byte) {
	t.Helper()
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

// ── helpers ───────────────────────────────────────────────────────────────────

func mockSoftware() []software.SoftwareInfo {
	now := time.Now().UTC().Format(time.RFC3339)
	return []software.SoftwareInfo{
		{
			Name:             "test-package",
			Source:           "deb_packages",
			InstalledVersion: "1.0.0",
			Type:             "deb_packages",
			DisplayName:      "Test Package",
			SoftwarePackage:  "test-package",
			FirstSeenAt:      now,
		},
		{
			Name:        "chrome-extension",
			Source:      "chrome_extensions",
			Type:        "chrome_extensions",
			DisplayName: "Chrome Extension",
			FilePath:    "/path/to/extension",
		},
		{
			Name:   "minimal-package",
			Source: "snap_packages",
			Type:   "snap_packages",
		},
	}
}

// ── NewSoftwareService ────────────────────────────────────────────────────────

func TestNewSoftwareService(t *testing.T) {
	svc := software.NewSoftwareService()
	if svc == nil {
		t.Fatal("NewSoftwareService() returned nil")
	}
}

// ── SendByRPC_MissingSupabaseURL ──────────────────────────────────────────────

func TestSendByRPC_MissingSupabaseURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	svc := software.NewSoftwareService()

	err := svc.SendByRPC(ctx, "some-agent-id", mockSoftware(), nil)
	if err == nil {
		t.Fatal("expected error for missing Supabase URL, got nil")
	}
	t.Logf("✅ SendByRPC correctly returned error for missing URL: %v", err)
}

// ── SendByRPC_Unauthorized ────────────────────────────────────────────────────

func TestSendByRPC_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"not authenticated"}`))
	}))
	defer server.Close()

	cfg := &config.Config{SupabaseURL: server.URL, AccessToken: "expired-token", DeviceID: "dev-1"}
	svc := software.NewSoftwareService()
	svc.SetSupabaseURL(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := svc.SendByRPC(ctx, cfg.DeviceID, mockSoftware(), cfg); err == nil {
		t.Fatal("expected error for 401 unauthorized, got nil")
	}
}

// ── TestSoftwareEnqueueRPC ────────────────────────────────────────────────────

func TestSoftwareEnqueueRPC(t *testing.T) {
	var rpCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/rest/v1/rpc/agent_enqueue_software") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected Content-Type: %s", r.Header.Get("Content-Type"))
		}
		rpCalled = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"enqueued":true,"agent_id":"dev-1","queue":"agent_ingest_software","msg_id":1}`))
	}))
	defer server.Close()

	svc := software.NewSoftwareService()
	svc.SetSupabaseURL(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := svc.SendByRPC(ctx, "dev-1", mockSoftware(), nil); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	if !rpCalled {
		t.Error("expected RPC endpoint to be called")
	}
}

// ── TestSoftwareEnqueue_StripsNUL ────────────────────────────────────────────

func TestSoftwareEnqueue_StripsNUL(t *testing.T) {
	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"msg_id":1}`))
	}))
	defer server.Close()

	svc := software.NewSoftwareService()
	svc.SetSupabaseURL(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// NUL bytes embedded in collected fields must not survive into the payload.
	list := []software.SoftwareInfo{
		{Name: "Bad\x00Name", Source: "deb_packages", Type: "deb_packages", InstalledVersion: "1.0\x000", FilePath: "/opt/x\x00y"},
	}
	if err := svc.SendByRPC(ctx, "dev-1", list, nil); err != nil {
		t.Fatalf("SendByRPC: %v", err)
	}
	assertNoNUL(t, body)
}

// ── TestSoftwareEnqueuePayloadShape ──────────────────────────────────────────

func TestSoftwareEnqueuePayloadShape(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer test-api-key") {
			t.Errorf("unexpected Authorization header: %s", r.Header.Get("Authorization"))
		}

		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		inner, _ := payload["payload"].(map[string]interface{})
		if inner == nil {
			t.Error("expected top-level 'payload' key")
		} else if inner["software"] == nil {
			t.Error("expected payload.software to be present")
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"enqueued":true,"msg_id":2}`))
	}))
	defer server.Close()

	cfg := &config.Config{SupabaseURL: server.URL, AccessToken: "test-api-key"}
	svc := software.NewSoftwareService()
	svc.SetSupabaseURL(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	now := time.Now().Format(time.RFC3339)
	list := []software.SoftwareInfo{
		{Name: "Pkg 1", Source: "deb_packages", InstalledVersion: "1.0.0", Type: "deb_packages", FirstSeenAt: now},
		{Name: "Pkg 2", Source: "snap_packages", InstalledVersion: "2.0.0", Type: "snap_packages", FirstSeenAt: now},
	}

	if err := svc.SendByRPC(ctx, "dev-1", list, cfg); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}
