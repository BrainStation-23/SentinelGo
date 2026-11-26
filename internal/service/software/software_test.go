package software_test

import (
	"context"
	"encoding/json"
	"fmt"
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

// ── TestSoftwareEnqueueMetadataFields ────────────────────────────────────────

// The optional metadata fields are sent under their own names when set and
// left out entirely when the collector had no value.
func TestSoftwareEnqueueMetadataFields(t *testing.T) {
	var items []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Payload struct {
				Software []map[string]any `json:"software"`
			} `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		items = payload.Payload.Software
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"enqueued":true,"msg_id":3}`))
	}))
	defer server.Close()

	svc := software.NewSoftwareService()
	svc.SetSupabaseURL(server.URL)
	list := []software.SoftwareInfo{
		{
			Name: "Slack", Source: "applications", Type: "applications",
			Publisher: "Slack Technologies, Inc.", InstallDate: "2026-01-02T03:04:05Z",
			SizeBytes: 123456, Architecture: "universal", BundleID: "com.tinyspeck.slackmacgap",
		},
		{Name: "bare", Source: "deb_packages", Type: "deb_packages"},
	}
	if err := svc.SendByRPC(context.Background(), "dev-1", list, nil); err != nil {
		t.Fatalf("SendByRPC: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2", len(items))
	}

	want := map[string]any{
		"publisher":    "Slack Technologies, Inc.",
		"install_date": "2026-01-02T03:04:05Z",
		"size_bytes":   float64(123456),
		"architecture": "universal",
		"bundle_id":    "com.tinyspeck.slackmacgap",
	}
	for k, v := range want {
		if items[0][k] != v {
			t.Errorf("items[0][%q] = %v, want %v", k, items[0][k], v)
		}
		if _, ok := items[1][k]; ok {
			t.Errorf("items[1] has %q; empty metadata must be omitted", k)
		}
	}
}

// ── TestSoftwareEnqueueWindowsIdentifiers ────────────────────────────────────

// enqueueCapture starts a server that records the software items of each
// agent_enqueue_software call and the raw request body size.
func enqueueCapture(t *testing.T) (*software.SoftwareService, *[]map[string]any, *int) {
	t.Helper()
	var items []map[string]any
	var size int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		size = len(body)
		var payload struct {
			Payload struct {
				Software []map[string]any `json:"software"`
			} `json:"payload"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		items = payload.Payload.Software
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"enqueued":true,"msg_id":4}`))
	}))
	t.Cleanup(server.Close)
	svc := software.NewSoftwareService()
	svc.SetSupabaseURL(server.URL)
	return svc, &items, &size
}

// The Windows identifiers (#562) are sent under the names the console reads
// and left out when empty, so an older console that ignores them is unaffected.
func TestSoftwareEnqueueWindowsIdentifiers(t *testing.T) {
	svc, items, _ := enqueueCapture(t)
	list := []software.SoftwareInfo{
		{
			Name: "Microsoft Visual C++ 2022 X64 Minimum Runtime", Source: "programs", Type: "programs",
			ProductCode: "{A181A302-3F6D-4BAD-97A8-A426A6499D78}", SystemComponent: true,
			ParentKeyName: "VC_Redist", ReleaseType: "Update", HomepageURL: "https://visualstudio.microsoft.com",
		},
		{
			Name: "Microsoft.WindowsTerminal", Source: "microsoft_store", Type: "microsoft_store",
			PackageFamilyName: "Microsoft.WindowsTerminal_8wekyb3d8bbwe",
		},
		{Name: "bad homepage", Source: "programs", Type: "programs", HomepageURL: "javascript:alert(1)"},
	}
	if err := svc.SendByRPC(context.Background(), "dev-1", list, nil); err != nil {
		t.Fatalf("SendByRPC: %v", err)
	}
	if len(*items) != 3 {
		t.Fatalf("got %d items, want 3", len(*items))
	}
	got := *items

	want := map[string]any{
		"product_code":     "{A181A302-3F6D-4BAD-97A8-A426A6499D78}",
		"system_component": true,
		"parent_key_name":  "VC_Redist",
		"release_type":     "Update",
		"homepage_url":     "https://visualstudio.microsoft.com",
	}
	for k, v := range want {
		if got[0][k] != v {
			t.Errorf("items[0][%q] = %v, want %v", k, got[0][k], v)
		}
		if _, ok := got[1][k]; ok {
			t.Errorf("items[1] has %q; empty fields must be omitted", k)
		}
	}
	if got[1]["package_family_name"] != "Microsoft.WindowsTerminal_8wekyb3d8bbwe" {
		t.Errorf("items[1][package_family_name] = %v", got[1]["package_family_name"])
	}
	if _, ok := got[0]["package_family_name"]; ok {
		t.Error("items[0] has package_family_name; empty fields must be omitted")
	}
	if _, ok := got[2]["homepage_url"]; ok {
		t.Error("a non-http(s) homepage must not be sent")
	}
}

// A large Windows inventory with every new field filled stays well under the
// ingest cap (agent_enqueue rejects a payload over 1 MiB).
func TestSoftwareEnqueueWindowsPayloadSize(t *testing.T) {
	const programs = 600
	const ingestCap = 1 << 20

	svc, items, size := enqueueCapture(t)
	list := make([]software.SoftwareInfo, 0, programs)
	for i := range programs {
		list = append(list, software.SoftwareInfo{
			Name:             fmt.Sprintf("Contoso Example Application %03d (x64)", i),
			Source:           "programs",
			Type:             "programs",
			InstalledVersion: "123.45.6789.0",
			FilePath:         fmt.Sprintf(`C:\Program Files\Contoso\Example Application %03d\`, i),
			FirstSeenAt:      "2026-11-26T00:00:00Z",
			Publisher:        "Contoso Software Corporation",
			InstallDate:      "2026-11-26T00:00:00Z",
			SizeBytes:        123456789,
			Architecture:     "x64",
			ProductCode:      fmt.Sprintf("{%08X-3F6D-4BAD-97A8-A426A6499D78}", i),
			SystemComponent:  i%3 == 0,
			ParentKeyName:    "Contoso Example Suite",
			ReleaseType:      "Security Update",
			HomepageURL:      fmt.Sprintf("https://www.contoso.example.com/products/example-application-%03d", i),
		})
	}
	if err := svc.SendByRPC(context.Background(), "dev-1", list, nil); err != nil {
		t.Fatalf("SendByRPC: %v", err)
	}
	if len(*items) != programs {
		t.Fatalf("got %d items, want %d", len(*items), programs)
	}
	t.Logf("%d programs: %d bytes (%.0f%% of the %d-byte ingest cap)", programs, *size, 100*float64(*size)/ingestCap, ingestCap)
	if *size > ingestCap/2 {
		t.Errorf("payload is %d bytes, over half the %d-byte ingest cap", *size, ingestCap)
	}
}
