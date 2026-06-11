package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/osinfo/shared"
	"sentinelgo/internal/service/rpcutil"

	postgrest "github.com/supabase-community/postgrest-go"
)

// rpcTimeout bounds a single Supabase RPC so a hung connection cannot wedge the
// scheduled task that calls it.
const rpcTimeout = 60 * time.Second

// AgentUpdatePayload represents data structure for updating agent information
type AgentUpdatePayload struct {
	Status           string      `json:"status"`
	Hostname         string      `json:"hostname"`
	ComputerName     string      `json:"computer_name"`
	CPUInfo          interface{} `json:"cpu_info"`
	SerialNumber     string      `json:"serial_number"`
	HardwareModel    string      `json:"hardware_model"`
	LocalUsers       interface{} `json:"local_users"`
	BatteryCondition string      `json:"battery_condition,omitempty"`
	RAMS             interface{} `json:"rams,omitempty"`
	Display          interface{} `json:"display,omitempty"`
	AgentVersion     string      `json:"agent_version,omitempty"`
	FQDN             string      `json:"fqdn,omitempty"`
	ChassisType      string      `json:"chassis_type,omitempty"`
	KernelVersion    string      `json:"kernel_version,omitempty"`
	GPUs             interface{} `json:"gpus,omitempty"`
	Disks            interface{} `json:"disks,omitempty"`
	Firmware         interface{} `json:"firmware,omitempty"`
	TPMVersion       string      `json:"tpm_version,omitempty"`
	NetworkAdapters  interface{} `json:"network_adapters,omitempty"`
	Peripherals      interface{} `json:"peripherals,omitempty"`
	AudioDevices     interface{} `json:"audio_devices,omitempty"`
	Printers         interface{} `json:"printers,omitempty"`
	OSInformation    interface{} `json:"os_information"`
	SecurityInfo     interface{} `json:"security_info,omitempty"`
}

// AgentService handles agent-related database operations via the PostgREST SDK.
type AgentService struct{}

// NewAgentService creates a new instance of AgentService.
func NewAgentService() *AgentService {
	return &AgentService{}
}

// newPostgrestClient builds a postgrest-go client authenticated with the
// current access token. A new client is created per call because the token
// rotates on every refresh.
func newPostgrestClient(supabaseURL, anonKey, accessToken string) *postgrest.Client {
	return postgrest.NewClient(
		supabaseURL+"/rest/v1",
		"public",
		map[string]string{
			"Authorization": "Bearer " + accessToken,
			"apikey":        anonKey,
		},
	)
}

// UpdateAgentInfo updates agent information in the agents table via the
// PostgREST SDK.
func (s *AgentService) UpdateAgentInfo(ctx context.Context, cfg *config.Config, sysInfo *shared.SystemInfo) error {
	hardwareModel := getHardwareModel()
	firmware := map[string]interface{}{
		"type":    sysInfo.FirmwareType,
		"vendor":  sysInfo.FirmwareVendor,
		"version": sysInfo.FirmwareVersion,
	}
	payload := AgentUpdatePayload{
		Status:           "active",
		Hostname:         sysInfo.Hostname,
		ComputerName:     sysInfo.Hostname,
		CPUInfo:          sysInfo.CPUInfoDetailed,
		SerialNumber:     sysInfo.SerialNumber,
		HardwareModel:    hardwareModel,
		BatteryCondition: sysInfo.BatteryCondition,
		RAMS:             sysInfo.RAMs,
		LocalUsers:       sysInfo.LocalUsers,
		Display:          sysInfo.Displays,
		AgentVersion:     sysInfo.AgentVersion,
		FQDN:             sysInfo.FQDN,
		ChassisType:      sysInfo.ChassisType,
		KernelVersion:    sysInfo.KernelVersion,
		GPUs:             sysInfo.GPUs,
		Disks:            sysInfo.Disks,
		Firmware:         firmware,
		TPMVersion:       sysInfo.TPMVersion,
		NetworkAdapters:  sysInfo.NetworkAdapters,
		Peripherals:      sysInfo.Peripherals,
		AudioDevices:     sysInfo.AudioDevices,
		Printers:         sysInfo.Printers,
		OSInformation:    sysInfo.OSInformation,
		SecurityInfo:     sysInfo.SecurityInfo,
	}

	client := newPostgrestClient(cfg.SupabaseURL, cfg.SupabaseKey, cfg.GetAccessToken())
	rawResult, err := rpcutil.CallWithTimeout(ctx, rpcTimeout, func() (string, error) {
		return client.Rpc("agent_push_inventory", "", map[string]interface{}{
			"payload": payload,
		}), client.ClientError
	})
	if err != nil {
		return fmt.Errorf("call agent_push_inventory RPC: %w", err)
	}
	if rawResult == "" {
		return fmt.Errorf("call agent_push_inventory RPC: empty response")
	}

	var raw interface{}
	if err := json.Unmarshal([]byte(rawResult), &raw); err != nil {
		return fmt.Errorf("agent_push_inventory: unexpected response: %w", err)
	}
	if obj, ok := raw.(map[string]interface{}); ok {
		if msg, ok := obj["message"]; ok {
			return fmt.Errorf("agent_push_inventory error: %v", msg)
		}
	}

	return nil
}

// SetAgentStatus updates only the agent status column via the PostgREST SDK.
func (s *AgentService) SetAgentStatus(ctx context.Context, cfg *config.Config, status string) error {
	client := newPostgrestClient(cfg.SupabaseURL, cfg.SupabaseKey, cfg.GetAccessToken())
	_, _, err := client.From("agents").
		Update(map[string]string{"status": status}, "minimal", "").
		ExecuteWithContext(ctx)
	if err != nil {
		return fmt.Errorf("update agent status: %w", err)
	}
	return nil
}

// GetAgentInfo retrieves agent information from the agents table via the
// PostgREST SDK.
func (s *AgentService) GetAgentInfo(ctx context.Context, cfg *config.Config) (map[string]interface{}, error) {
	client := newPostgrestClient(cfg.SupabaseURL, cfg.SupabaseKey, cfg.GetAccessToken())

	var agents []map[string]interface{}
	_, err := client.From("agents").
		Select("*", "", false).
		ExecuteToWithContext(ctx, &agents)
	if err != nil {
		return nil, fmt.Errorf("get agent info: %w", err)
	}

	if len(agents) == 0 {
		return nil, fmt.Errorf("agent not found")
	}

	return agents[0], nil
}
