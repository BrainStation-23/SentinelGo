package auditlog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/httpx"
	"sentinelgo/internal/models"
	"sentinelgo/internal/sanitize"
	"sentinelgo/internal/service/rpcutil"
	"sentinelgo/internal/supabase"
)

const (
	rpcEnqueueAuditLogs = "agent_enqueue_audit_logs"
	headerXDeviceID     = "X-Device-ID"
)

// ErrInvalidInput is returned when an audit log is missing required fields.
var ErrInvalidInput = errors.New("invalid audit log input")

// AuditLogService handles audit log operations with batch processing
type AuditLogService struct {
	config *config.Config
	client *http.Client
}

// NewAuditLogService creates a new audit log service
func NewAuditLogService(cfg *config.Config) *AuditLogService {
	return &AuditLogService{
		config: cfg,
		client: httpx.NewClient(30 * time.Second),
	}
}

// LogOSEvent validates and sends an OS event audit log
func (s *AuditLogService) LogOSEvent(ctx context.Context, input models.AuditLog) error {
	if input.DeviceID == "" {
		return ErrInvalidInput
	}
	return s.sendToSupabase(ctx, input)
}

// auditLogCategoryKey maps a log category to the grouped key used in the RPC payload.
func auditLogCategoryKey(category string) string {
	switch category {
	case models.LogCategorySecurity, models.LogCategoryUser:
		return "security"
	case models.LogCategoryNetwork:
		return "network"
	case models.LogCategoryPolicy, models.LogCategoryRemote:
		return "mdm"
	default: // SYSTEM_LOG, AGENT_LOG, STORAGE_LOG, and unknown
		return "system"
	}
}

// enqueue calls the audit-log enqueue RPC once with body (already-marshalled
// JSON). The access token is read from the config on every request.
func (s *AuditLogService) enqueue(ctx context.Context, body []byte) error {
	c := supabase.FromConfig(s.config, supabase.WithHTTPClient(s.client))
	return c.RPC(ctx, rpcEnqueueAuditLogs, json.RawMessage(body), nil,
		supabase.WithHeader(headerXDeviceID, s.config.DeviceID))
}

// sendToSupabase sends an audit log to the agent_enqueue_audit_logs RPC.
func (s *AuditLogService) sendToSupabase(ctx context.Context, auditLog models.AuditLog) error {
	entry := map[string]any{
		"event_type":   auditLog.EventType,
		"created_at":   auditLog.Timestamp,
		"severity":     auditLog.Severity,
		"log_category": auditLog.LogCategory,
		"source":       auditLog.Source,
		"event_data":   auditLog.EventData,
	}

	categoryKey := auditLogCategoryKey(auditLog.LogCategory)

	data, err := json.Marshal(map[string]any{
		"payload": map[string]any{
			"device_id":     s.config.DeviceID,
			"os_type":       auditLog.OSType,
			"agent_version": auditLog.AgentVersion,
			"source":        auditLog.Source,
			"logs":          []any{map[string]any{categoryKey: []any{entry}}},
		},
	})
	if err != nil {
		return fmt.Errorf("marshal audit log: %w", err)
	}
	// Postgres rejects NUL bytes in text/jsonb; strip any that survived collection.
	data = sanitize.StripJSONNUL(data)

	if err := s.enqueue(ctx, data); err != nil {
		return fmt.Errorf("audit log upload failed: %w", err)
	}
	return nil
}

// ProcessBatchLogs processes multiple audit logs from batch data
func (s *AuditLogService) ProcessBatchLogs(ctx context.Context, batchData map[string]any) error {
	agentID, ok := batchData["agent_id"].(string)
	if !ok {
		return fmt.Errorf("agent_id is required in batch data")
	}

	osType, ok := batchData["os_type"].(string)
	if !ok {
		return fmt.Errorf("os_type is required in batch data")
	}

	agentVersion, ok := batchData["agent_version"].(string)
	if !ok {
		return fmt.Errorf("agent_version is required in batch data")
	}

	source, ok := batchData["source"].(string)
	if !ok {
		return fmt.Errorf("source is required in batch data")
	}

	logs, ok := batchData["logs"].([]any)
	if !ok {
		return fmt.Errorf("logs array is required in batch data")
	}

	processedCount := 0
	for _, logEntry := range logs {
		logJSON, err := json.Marshal(logEntry)
		if err != nil {
			log.Printf("warning: failed to marshal log entry: %v", err)
			continue
		}

		var auditLog models.AuditLog
		if err := json.Unmarshal(logJSON, &auditLog); err != nil {
			log.Printf("warning: failed to parse log entry: %v", err)
			continue
		}

		auditLog.AgentID = agentID
		auditLog.DeviceID = agentID
		auditLog.OSType = osType
		auditLog.AgentVersion = agentVersion
		auditLog.Source = source

		if err := s.sendToSupabase(ctx, auditLog); err != nil {
			log.Printf("warning: failed to send batch log entry: %v", err)
			continue
		}

		processedCount++
	}

	log.Printf("successfully processed %d log entries from batch", processedCount)
	return nil
}

// SendBatchLogs sends the batch data to the Supabase batch-logs endpoint.
// Prefer SendBatchLogsWithContext when a context is available.
func (s *AuditLogService) SendBatchLogs(batchData map[string]any) error {
	return s.SendBatchLogsWithContext(context.Background(), batchData)
}

// SendBatchLogsWithContext sends a batch of audit logs using the provided context.
// It applies the standard enqueue retry policy: 5xx and network errors are retried
// with exponential backoff (1 s initial, 5 min cap); 401 is propagated for the
// caller's DoWithAuthRetry to handle; other 4xx errors are logged and dropped.
func (s *AuditLogService) SendBatchLogsWithContext(ctx context.Context, batchData map[string]any) error {
	if s.config.SupabaseURL == "" {
		return fmt.Errorf("supabase URL not configured")
	}

	data, err := json.Marshal(batchData)
	if err != nil {
		return fmt.Errorf("marshal batch data: %w", err)
	}
	// Postgres rejects NUL bytes in text/jsonb; strip any that survived collection.
	data = sanitize.StripJSONNUL(data)

	log.Printf("Audit Service: uploading batch (%d bytes)", len(data))

	return rpcutil.WithEnqueueRetry(ctx, func(ctx context.Context) error {
		if err := s.enqueue(ctx, data); err != nil {
			return fmt.Errorf("batch logs upload failed: %w", err)
		}
		return nil
	})
}
