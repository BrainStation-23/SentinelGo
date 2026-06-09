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

// ErrInvalidInput is returned when an audit log is missing required fields.
var ErrInvalidInput = errors.New("invalid audit log input")

// AppConfig holds application configuration from command line flags
type AppConfig struct {
	ConfigPath    string
	EventType     string
	OSType        string
	OSVerBefore   string
	OSVerAfter    string
	UptimeSeconds int64
}

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

// sendToSupabase sends an audit log to the agent_insert_audit_logs_batch RPC.
func (s *AuditLogService) sendToSupabase(ctx context.Context, auditLog models.AuditLog) error {
	entry := map[string]interface{}{
		"event_type":   auditLog.EventType,
		"created_at":   auditLog.Timestamp,
		"severity":     auditLog.Severity,
		"log_category": auditLog.LogCategory,
		"source":       auditLog.Source,
		"event_data":   auditLog.EventData,
	}

	categoryKey := auditLogCategoryKey(auditLog.LogCategory)

	data, err := json.Marshal(map[string]interface{}{
		"payload": map[string]interface{}{
			"device_id":     s.config.DeviceID,
			"os_type":       auditLog.OSType,
			"agent_version": auditLog.AgentVersion,
			"source":        auditLog.Source,
			"logs":          []interface{}{map[string]interface{}{categoryKey: []interface{}{entry}}},
		},
	})
	if err != nil {
		return fmt.Errorf("marshal audit log: %w", err)
	}

	url := s.config.SupabaseURL + "/rest/v1/rpc/agent_insert_audit_logs_batch"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.config.AccessToken)
	req.Header.Set("X-Device-ID", s.config.DeviceID)
	req.Header.Set("apikey", s.config.SupabaseKey)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send audit log: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			_ = err
		}
	}()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("audit log upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ProcessBatchLogs processes multiple audit logs from batch data
func (s *AuditLogService) ProcessBatchLogs(ctx context.Context, batchData map[string]interface{}) error {
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

	logs, ok := batchData["logs"].([]interface{})
	if !ok {
		return fmt.Errorf("logs array is required in batch data")
	}

	processedCount := 0
	for _, logEntry := range logs {
		logJSON, err := json.Marshal(logEntry)
		if err != nil {
			fmt.Printf("Warning: Failed to marshal log entry: %v\n", err)
			continue
		}

		var auditLog models.AuditLog
		if err := json.Unmarshal(logJSON, &auditLog); err != nil {
			fmt.Printf("Warning: Failed to parse log entry: %v\n", err)
			continue
		}

		auditLog.AgentID = agentID
		auditLog.DeviceID = agentID
		auditLog.OSType = osType
		auditLog.AgentVersion = agentVersion
		auditLog.Source = source

		if err := s.sendToSupabase(ctx, auditLog); err != nil {
			fmt.Printf("Warning: Failed to send batch log entry: %v\n", err)
			continue
		}

		processedCount++
	}

	fmt.Printf("Successfully processed %d log entries from batch\n", processedCount)
	return nil
}

// GenerateSystemLogs generates system log entries
func (s *AuditLogService) GenerateSystemLogs(appCfg *AppConfig) []map[string]interface{} {
	var systemLogs []map[string]interface{}

	systemLogs = append(systemLogs, map[string]interface{}{
		"event_type":   appCfg.EventType,
		"created_at":   time.Now().UTC().Format(time.RFC3339),
		"severity":     "low",
		"log_category": "SYSTEM_LOG",
		"event_data": map[string]interface{}{
			"os_version_before": appCfg.OSVerBefore,
			"os_version_after":  appCfg.OSVerAfter,
			"uptime_seconds":    appCfg.UptimeSeconds,
		},
	})

	if appCfg.EventType == "upgrade" {
		systemLogs = append(systemLogs, map[string]interface{}{
			"event_type":   "upgrade",
			"created_at":   time.Now().UTC().Format(time.RFC3339),
			"severity":     "low",
			"log_category": "SYSTEM_LOG",
			"event_data": map[string]interface{}{
				"os_version_before": appCfg.OSVerBefore,
				"os_version_after":  appCfg.OSVerAfter,
				"source":            "package_manager",
				"detection":         "automatic",
				"action_taken":      "System upgrade completed",
			},
		})
	}

	return systemLogs
}

// GenerateSecurityLogs generates security log entries
func (s *AuditLogService) GenerateSecurityLogs(appCfg *AppConfig) []map[string]interface{} {
	var securityLogs []map[string]interface{}

	securityLogs = append(securityLogs, map[string]interface{}{
		"event_type":   "local_login_success",
		"created_at":   time.Now().UTC().Format(time.RFC3339),
		"severity":     "medium",
		"log_category": "SECURITY_LOG",
		"event_data": map[string]interface{}{
			"authentication_source": "local_pc",
			"action_taken":          "session opened",
			"username":              "system_user",
			"account_type":          "user",
			"login_method":          "password",
		},
	})

	return securityLogs
}

// GenerateMDMLogs generates MDM (Mobile Device Management) log entries
func (s *AuditLogService) GenerateMDMLogs(appCfg *AppConfig) []map[string]interface{} {
	var mdmLogs []map[string]interface{}

	mdmLogs = append(mdmLogs, map[string]interface{}{
		"event_type":   "policy_applied",
		"created_at":   time.Now().UTC().Format(time.RFC3339),
		"severity":     "medium",
		"log_category": "POLICY_LOG",
		"event_data": map[string]interface{}{
			"policy_id":      "POL-001",
			"policy_type":    "security",
			"apply_status":   "success",
			"initiated_by":   "system",
			"policy_name":    "Default Security Policy",
			"rules_applied":  5,
			"execution_time": "2s",
		},
	})

	return mdmLogs
}

// GenerateNetworkLogs generates network log entries
func (s *AuditLogService) GenerateNetworkLogs(appCfg *AppConfig) []map[string]interface{} {
	var networkLogs []map[string]interface{}

	networkLogs = append(networkLogs, map[string]interface{}{
		"event_type":   "connection_established",
		"created_at":   time.Now().UTC().Format(time.RFC3339),
		"severity":     "low",
		"log_category": "NETWORK_LOG",
		"event_data": map[string]interface{}{
			"interface_name":    "eth0",
			"network_type":      "ethernet",
			"connection_status": "connected",
			"ip_address":        "192.168.1.100",
			"gateway":           "192.168.1.1",
			"dns_servers":       []string{"192.168.1.1", "8.8.8.8"},
		},
	})

	return networkLogs
}

// CreateBatchData creates the complete batch JSON structure
func (s *AuditLogService) CreateBatchData(appCfg *AppConfig) map[string]interface{} {
	systemLogs := s.GenerateSystemLogs(appCfg)
	securityLogs := s.GenerateSecurityLogs(appCfg)
	mdmLogs := s.GenerateMDMLogs(appCfg)
	networkLogs := s.GenerateNetworkLogs(appCfg)

	logs := []map[string]interface{}{
		{"system": systemLogs},
		{"security": securityLogs},
		{"mdm": mdmLogs},
		{"network": networkLogs},
	}

	return map[string]interface{}{
		"payload": map[string]interface{}{
			"device_id":     s.config.DeviceID,
			"os_type":       appCfg.OSType,
			"agent_version": s.config.CurrentVersion,
			"source":        "agent",
			"logs":          logs,
		},
	}
}

// SendBatchLogs sends the batch data to Supabase batch-logs endpoint
func (s *AuditLogService) SendBatchLogs(batchData map[string]interface{}) error {
	data, err := json.Marshal(batchData)
	if err != nil {
		return fmt.Errorf("marshal batch data: %w", err)
	}

	url := s.config.SupabaseURL + "/rest/v1/rpc/agent_insert_audit_logs_batch"
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create batch request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.config.AccessToken)
	req.Header.Set("X-Device-ID", s.config.DeviceID)
	req.Header.Set("apikey", s.config.SupabaseKey)

	log.Printf("request data from Audit Service: %s", string(data))

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send batch logs: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			err = closeErr
		}
	}()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("batch logs upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// SendBatchLogsWithContext sends a batch of audit logs using the provided context.
func (s *AuditLogService) SendBatchLogsWithContext(ctx context.Context, batchData map[string]interface{}) error {
	data, err := json.Marshal(batchData)
	if err != nil {
		return fmt.Errorf("marshal batch data: %w", err)
	}

	url := s.config.SupabaseURL + "/rest/v1/rpc/agent_insert_audit_logs_batch"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create batch request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.config.AccessToken)
	req.Header.Set("X-Device-ID", s.config.DeviceID)
	req.Header.Set("apikey", s.config.SupabaseKey)

	resp, err := s.client.Do(req)
	log.Printf("request data from Audit Service: %s", string(data))

	if err != nil {
		return fmt.Errorf("send batch logs: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			err = closeErr
		}
	}()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("batch logs upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

