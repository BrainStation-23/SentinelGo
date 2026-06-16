package auditlog_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/models"
	"sentinelgo/internal/service/auditlog"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func auditLogCfg(supabaseURL, deviceID, accessToken string) *config.Config {
	return &config.Config{
		SupabaseURL: supabaseURL,
		DeviceID:    deviceID,
		AccessToken: accessToken,
	}
}

func sampleAuditLog(deviceID string) models.AuditLog {
	return models.AuditLog{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		AgentID:      deviceID,
		DeviceID:     deviceID,
		LogCategory:  "SECURITY_LOG",
		EventType:    "local_login_success",
		OSType:       "linux",
		AgentVersion: "2.1.5",
		Severity:     "medium",
		Source:       "agent",
		EventData:    json.RawMessage(`{"username":"testuser","login_method":"password"}`),
	}
}

func newAuditLogServer(t *testing.T, handler func(w http.ResponseWriter, body map[string]interface{})) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/rpc/agent_enqueue_audit_logs") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		handler(w, body)
	}))
}

func keys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ── NewAuditLogService ────────────────────────────────────────────────────────

func TestNewAuditLogService(t *testing.T) {
	cfg := &config.Config{}
	als := auditlog.NewAuditLogService(cfg)
	if als == nil {
		t.Fatal("NewAuditLogService() returned nil")
	}
}

func TestNewAuditLogService_NilConfig(t *testing.T) {
	als := auditlog.NewAuditLogService(nil)
	if als == nil {
		t.Fatal("NewAuditLogService() should handle nil config")
	}
}

// ── ProcessBatchLogs validation ───────────────────────────────────────────────

func TestProcessBatchLogs_MissingAgentID(t *testing.T) {
	svc := auditlog.NewAuditLogService(&config.Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := svc.ProcessBatchLogs(ctx, map[string]interface{}{
		"os_type":       "linux",
		"agent_version": "v1", "source": "agent", "logs": []interface{}{},
	})
	if err == nil || !strings.Contains(err.Error(), "agent_id") {
		t.Fatalf("expected agent_id error, got: %v", err)
	}
}

func TestProcessBatchLogs_MissingOSType(t *testing.T) {
	svc := auditlog.NewAuditLogService(&config.Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := svc.ProcessBatchLogs(ctx, map[string]interface{}{
		"agent_id":      "a1",
		"agent_version": "v1", "source": "agent", "logs": []interface{}{},
	})
	if err == nil || !strings.Contains(err.Error(), "os_type") {
		t.Fatalf("expected os_type error, got: %v", err)
	}
}

func TestProcessBatchLogs_MissingSource(t *testing.T) {
	svc := auditlog.NewAuditLogService(&config.Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := svc.ProcessBatchLogs(ctx, map[string]interface{}{
		"agent_id": "a1", "os_type": "linux",
		"agent_version": "v1", "logs": []interface{}{},
	})
	if err == nil || !strings.Contains(err.Error(), "source") {
		t.Fatalf("expected source error, got: %v", err)
	}
}

func TestProcessBatchLogs_MissingLogs(t *testing.T) {
	svc := auditlog.NewAuditLogService(&config.Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := svc.ProcessBatchLogs(ctx, map[string]interface{}{
		"agent_id": "a1", "os_type": "linux",
		"agent_version": "v1", "source": "agent",
	})
	if err == nil || !strings.Contains(err.Error(), "logs") {
		t.Fatalf("expected logs error, got: %v", err)
	}
}

// ── SendBatchLogs ─────────────────────────────────────────────────────────────

func batchLog(eventType, createdAt, severity, category string, eventData map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"event_type":   eventType,
		"created_at":   createdAt,
		"severity":     severity,
		"log_category": category,
		"event_data":   eventData,
	}
}

func wrapPayload(inner map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"payload": inner}
}

func innerPayload(deviceID, osType, agentVersion string, logs []map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"device_id":     deviceID,
		"os_type":       osType,
		"agent_version": agentVersion,
		"source":        "agent",
		"logs":          logs,
	}
}

func sampleBatchPayload(deviceID string) map[string]interface{} {
	now := time.Now().UTC().Format(time.RFC3339)
	return wrapPayload(innerPayload(deviceID, "macOS", "1.4.2",
		[]map[string]interface{}{
			{"system": []map[string]interface{}{
				batchLog("boot", now, "low", "system",
					map[string]interface{}{"uptime": 60}),
			}},
		},
	))
}

func TestSendBatchLogs_Success(t *testing.T) {
	srv := newAuditLogServer(t, func(w http.ResponseWriter, _ map[string]interface{}) {
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	cfg := auditLogCfg(srv.URL, "dev-1", "tok")
	svc := auditlog.NewAuditLogService(cfg)
	if err := svc.SendBatchLogs(sampleBatchPayload("dev-1")); err != nil {
		t.Fatalf("SendBatchLogs: %v", err)
	}
}

func TestProcessBatchLogs_MissingAgentVersion(t *testing.T) {
	svc := auditlog.NewAuditLogService(&config.Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := svc.ProcessBatchLogs(ctx, map[string]interface{}{
		"agent_id": "a1", "os_type": "linux",
		"source": "agent", "logs": []interface{}{},
	})
	if err == nil || !strings.Contains(err.Error(), "agent_version") {
		t.Fatalf("expected agent_version error, got: %v", err)
	}
}

func TestSendBatchLogs_MissingURL(t *testing.T) {
	svc := auditlog.NewAuditLogService(&config.Config{SupabaseURL: ""})
	now := time.Now().UTC().Format(time.RFC3339)
	payload := wrapPayload(innerPayload("dev-1", "linux", "v2.1.5",
		[]map[string]interface{}{
			{"system": []map[string]interface{}{
				batchLog("boot", now, "low", "system",
					map[string]interface{}{"uptime": 60}),
			}},
		},
	))
	err := svc.SendBatchLogs(payload)
	if err == nil {
		t.Fatal("expected error for empty Supabase URL, got nil")
	}
	t.Logf("✅ SendBatchLogs correctly returned error for missing URL: %v", err)
}

func TestAuditLogBatchRPC_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "invalid token"})
	}))
	defer server.Close()

	cfg := &config.Config{SupabaseURL: server.URL, DeviceID: "dev-1", AccessToken: "expired"}
	svc := auditlog.NewAuditLogService(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := svc.SendBatchLogsWithContext(ctx, sampleBatchPayload(cfg.DeviceID)); err == nil {
		t.Fatal("expected error for 401 unauthorized, got nil")
	}
}

func TestAuditLogBatchRPC_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.Config{SupabaseURL: server.URL, DeviceID: "dev-1", AccessToken: "tok"}
	svc := auditlog.NewAuditLogService(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() { done <- svc.SendBatchLogsWithContext(ctx, sampleBatchPayload(cfg.DeviceID)) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error with cancelled context, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SendBatchLogsWithContext did not return within 5s with cancelled context")
	}
}

// ── sendToSupabase (via LogOSEvent) ───────────────────────────────────────────

func TestSendToSupabase_Success(t *testing.T) {
	server := newAuditLogServer(t, func(w http.ResponseWriter, _ map[string]interface{}) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	})
	defer server.Close()

	svc := auditlog.NewAuditLogService(auditLogCfg(server.URL, "dev-1", "tok"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := svc.LogOSEvent(ctx, sampleAuditLog("dev-1")); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestSendToSupabase_PayloadEnvelope(t *testing.T) {
	var captured map[string]interface{}

	server := newAuditLogServer(t, func(w http.ResponseWriter, body map[string]interface{}) {
		captured = body
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	log := sampleAuditLog("dev-payload")
	svc := auditlog.NewAuditLogService(auditLogCfg(server.URL, "dev-payload", "tok"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := svc.LogOSEvent(ctx, log); err != nil {
		t.Fatalf("LogOSEvent failed: %v", err)
	}

	inner, _ := captured["payload"].(map[string]interface{})
	if inner == nil {
		t.Fatalf("top-level 'payload' key missing; got keys: %v", keys(captured))
	}

	for _, field := range []string{"device_id", "os_type", "agent_version", "source", "logs"} {
		if _, ok := inner[field]; !ok {
			t.Errorf("payload missing field %q", field)
		}
	}

	if got, _ := inner["device_id"].(string); got != "dev-payload" {
		t.Errorf("device_id: want %q, got %q", "dev-payload", got)
	}

	logsArr, _ := inner["logs"].([]interface{})
	if len(logsArr) == 0 {
		t.Fatal("payload.logs must be a non-empty array")
	}
}

func TestSendToSupabase_400Error(t *testing.T) {
	server := newAuditLogServer(t, func(w http.ResponseWriter, _ map[string]interface{}) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"message": "bad request"})
	})
	defer server.Close()

	svc := auditlog.NewAuditLogService(auditLogCfg(server.URL, "dev-1", "tok"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := svc.LogOSEvent(ctx, sampleAuditLog("dev-1"))
	if err == nil {
		t.Fatal("expected error on 400, got nil")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error should mention status 400, got: %v", err)
	}
}

func TestSendToSupabase_MissingDeviceID(t *testing.T) {
	server := newAuditLogServer(t, func(w http.ResponseWriter, _ map[string]interface{}) {
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	svc := auditlog.NewAuditLogService(auditLogCfg(server.URL, "", "tok"))
	log := sampleAuditLog("")
	log.DeviceID = ""

	err := svc.LogOSEvent(context.Background(), log)
	if err == nil {
		t.Fatal("expected error for missing device ID, got nil")
	}
}

func TestSendToSupabase_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	svc := auditlog.NewAuditLogService(auditLogCfg(server.URL, "dev-1", "tok"))
	err := svc.LogOSEvent(ctx, sampleAuditLog("dev-1"))
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}
