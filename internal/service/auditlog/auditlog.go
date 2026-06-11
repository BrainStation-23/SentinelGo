package auditlog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/httpx"
	"sentinelgo/internal/models"
)

const (
	rpcInsertBatch      = "/rest/v1/rpc/agent_insert_audit_logs_batch"
	headerContentType   = "Content-Type"
	headerAuthorization = "Authorization"
	headerXDeviceID     = "X-Device-ID"
	mimeJSON            = "application/json"
	bearerPrefix        = "Bearer "
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

// newRequest builds a POST request to the batch RPC endpoint with all required headers set.
func (s *AuditLogService) newRequest(ctx context.Context, body []byte) (*http.Request, error) {
	url := s.config.SupabaseURL + rpcInsertBatch
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set(headerContentType, mimeJSON)
	req.Header.Set(headerAuthorization, bearerPrefix+s.config.AccessToken)
	req.Header.Set(headerXDeviceID, s.config.DeviceID)
	req.Header.Set("apikey", s.config.SupabaseKey)
	return req, nil
}

// doRequest executes the request and returns an error for non-2xx responses.
func (s *AuditLogService) doRequest(req *http.Request) error {
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("failed to close response body: %v", closeErr)
		}
	}()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// sendToSupabase sends an audit log to the agent_insert_audit_logs_batch RPC.
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

	req, err := s.newRequest(ctx, data)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	if err := s.doRequest(req); err != nil {
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
func (s *AuditLogService) SendBatchLogsWithContext(ctx context.Context, batchData map[string]any) error {
	data, err := json.Marshal(batchData)
	if err != nil {
		return fmt.Errorf("marshal batch data: %w", err)
	}

	// Log only the size, never the payload: a batch can contain up to 500 audit
	// events including usernames, hostnames and process command lines. Dumping
	// them into the agent's own log leaks sensitive data into logs of unknown
	// retention/permissions and bloats them.
	log.Printf("Audit Service: uploading batch (%d bytes)", len(data))

	req, err := s.newRequest(ctx, data)
	if err != nil {
		return fmt.Errorf("create batch request: %w", err)
	}

	if err := s.doRequest(req); err != nil {
		return fmt.Errorf("batch logs upload failed: %w", err)
	}
	return nil
}
