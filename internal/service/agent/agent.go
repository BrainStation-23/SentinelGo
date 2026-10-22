package agent

import (
	"context"
	"net/http"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/constants"
	"sentinelgo/internal/httpx"
	"sentinelgo/internal/osinfo/shared"
	"sentinelgo/internal/service/rpcutil"
	"sentinelgo/internal/supabase"
)

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
	// PowerTelemetry covers the time since the last successful upload
	// (#198); left out until a sampling interval has completed.
	PowerTelemetry *shared.PowerTelemetry `json:"power_telemetry,omitempty"`
	// Capabilities lists the task features this agent supports (contract
	// v1 §6). Always sent, even empty, so the backend can tell "none" from
	// an agent too old to report them.
	Capabilities []string `json:"capabilities"`
	// local_admin_members, signed_in_users, last_signed_in_user and
	// identity_join (#223), at the top level next to local_users. A list
	// that couldn't be read is sent as null.
	shared.UserIdentity
}

// AgentService handles agent-related database operations.
type AgentService struct {
	client *http.Client
}

// NewAgentService creates a new instance of AgentService.
func NewAgentService() *AgentService {
	return &AgentService{
		client: httpx.NewClient(30 * time.Second),
	}
}

// UpdateAgentInfo updates agent information via the agent_enqueue_inventory RPC.
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
		PowerTelemetry:   sysInfo.PowerTelemetry,
		Capabilities:     constants.Capabilities(),
		UserIdentity:     sysInfo.UserIdentity,
	}

	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	c := supabase.FromConfig(cfg, supabase.WithHTTPClient(s.client))
	params := map[string]interface{}{"payload": payload}
	return rpcutil.PostEnqueue(ctx, c, "agent_enqueue_inventory", params, "inventory")
}
