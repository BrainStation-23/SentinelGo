package software_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/service/software"
)

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
			Status:           "installed",
			FirstSeenAt:      now,
			LastSeenAt:       now,
			IsActive:         true,
		},
		{
			Name:        "chrome-extension",
			Source:      "chrome_extensions",
			Type:        "chrome_extensions",
			DisplayName: "Chrome Extension",
			FilePath:    "/path/to/extension",
			Status:      "installed",
			FirstSeenAt: now,
			LastSeenAt:  now,
			IsActive:    true,
		},
		{
			Name:        "minimal-package",
			Source:      "snap_packages",
			Type:        "snap_packages",
			FirstSeenAt: now,
			LastSeenAt:  now,
			IsActive:    true,
		},
	}
}

func newConfiguredService(supabaseURL, accessToken string) *software.SoftwareService {
	svc := &software.SoftwareService{}
	svc.SetSupabaseURL(supabaseURL)
	svc.SetEdgeFunctionConfig(supabaseURL+"/functions/v1/sync-software", accessToken)
	return svc
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

	svc := &software.SoftwareService{}

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
	svc := newConfiguredService(server.URL, "expired-token")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := svc.SendByRPC(ctx, cfg.DeviceID, mockSoftware(), cfg); err == nil {
		t.Fatal("expected error for 401 unauthorized, got nil")
	}
}

// ── TestSoftwareUpsertBasic ───────────────────────────────────────────────────

func TestSoftwareUpsertBasic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST request, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type 'application/json', got '%s'", r.Header.Get("Content-Type"))
		}

		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}

		inner, _ := payload["payload"].(map[string]interface{})
		if inner == nil {
			t.Error("request body should contain top-level 'payload' key")
		} else if inner["software"] == nil {
			t.Error("payload.software should be present")
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"processed":1}`))
	}))
	defer server.Close()

	svc := &software.SoftwareService{}
	svc.SetEdgeFunctionConfig(server.URL, "test-api-key")
	svc.SetSupabaseURL(server.URL)

	testSoftware := []software.SoftwareInfo{
		{
			ID:               1,
			Name:             "Test Software",
			Source:           "test-source",
			InstalledVersion: "1.0.0",
			Type:             "test-type",
			Status:           "installed",
			FirstSeenAt:      time.Now().Format(time.RFC3339),
			LastSeenAt:       time.Now().Format(time.RFC3339),
			IsActive:         true,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := svc.SendByRPC(ctx, "test-agent-id", testSoftware, nil); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

// ── TestSoftwareUpsertFallbackToRestAPI ───────────────────────────────────────

func TestSoftwareUpsertFallbackToRestAPI(t *testing.T) {
	restAPICalled := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/functions/v1/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if strings.Contains(r.URL.Path, "/rest/v1/rpc/") {
			restAPICalled = true
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"processed":1}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	svc := &software.SoftwareService{}
	svc.SetEdgeFunctionConfig(server.URL+"/functions/v1/upsert-agent-software", "test-api-key")

	testSoftware := []software.SoftwareInfo{
		{
			Name:             "Fallback Test Software",
			Source:           "deb_packages",
			InstalledVersion: "1.0.0",
			Type:             "deb_packages",
			Status:           "installed",
			LastSeenAt:       time.Now().Format(time.RFC3339),
			IsActive:         true,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := svc.SendSoftwareData(ctx, "test-agent-id", testSoftware); err != nil {
		t.Errorf("expected fallback to RPC to succeed, got: %v", err)
	}
	if !restAPICalled {
		t.Error("expected RPC fallback to be called after edge function 404")
	}
}

// ── TestSoftwareUpsertSetSupabaseURL ─────────────────────────────────────────

func TestSoftwareUpsertSetSupabaseURL(t *testing.T) {
	restAPICalled := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/rest/v1/rpc/") {
			restAPICalled = true
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"processed":1}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	svc := &software.SoftwareService{}
	svc.SetEdgeFunctionConfig(server.URL, "test-api-key")
	svc.SetSupabaseURL(server.URL)

	testSoftware := []software.SoftwareInfo{
		{Name: "SetSupabaseURL Test", Source: "homebrew", Type: "homebrew", Status: "installed", IsActive: true},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := svc.SendByRPC(ctx, "test-agent-id", testSoftware, nil); err != nil {
		t.Errorf("expected REST API fallback via SetSupabaseURL to succeed, got: %v", err)
	}
	if !restAPICalled {
		t.Error("expected REST API fallback to be called")
	}
}

// ── TestUpsertAPI ─────────────────────────────────────────────────────────────

func TestUpsertAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST request, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type 'application/json', got '%s'", r.Header.Get("Content-Type"))
		}
		if !strings.Contains(r.Header.Get("Authorization"), "Bearer test-api-key") {
			t.Errorf("expected Authorization header with Bearer test-api-key, got '%s'", r.Header.Get("Authorization"))
		}

		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}

		inner, _ := payload["payload"].(map[string]interface{})
		if inner == nil {
			t.Error("request body should contain top-level 'payload' key")
		} else if inner["software"] == nil {
			t.Error("payload.software should be present")
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"processed":2}`))
	}))
	defer server.Close()

	svc := &software.SoftwareService{}
	svc.SetEdgeFunctionConfig(server.URL, "test-api-key")
	svc.SetSupabaseURL(server.URL)

	now := time.Now().Format(time.RFC3339)
	testSoftware := []software.SoftwareInfo{
		{ID: 1, Name: "Integration Test Software 1", Source: "deb_packages", InstalledVersion: "1.0.0", Type: "deb_packages", Status: "installed", FirstSeenAt: now, LastSeenAt: now, IsActive: true},
		{ID: 2, Name: "Integration Test Software 2", Source: "snap_packages", InstalledVersion: "2.0.0", Type: "snap_packages", Status: "installed", FirstSeenAt: now, LastSeenAt: now, IsActive: true},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := svc.SendByRPC(ctx, "test-agent-id", testSoftware, nil); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}
