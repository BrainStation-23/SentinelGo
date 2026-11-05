package agent

import (
	"context"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/constants"
	"sentinelgo/internal/httpx"
	"sentinelgo/internal/localadmin"
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
	LocalUsers       interface{} `json:"local_users,omitempty"`
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
	// MDM is the device's MDM enrollment state (#349); left out on
	// platforms without a collector.
	MDM *shared.MDMInfo `json:"mdm,omitempty"`
	// PowerTelemetry covers the time since the last successful upload
	// (#198); left out until a sampling interval has completed.
	PowerTelemetry *shared.PowerTelemetry `json:"power_telemetry,omitempty"`
	// Sessions are the signed-in users' session helpers with their
	// capabilities, including notification readiness (#323). The DLP status
	// carries them too, but it isn't sent while DLP is off. Left out when
	// the agent runs no session helpers.
	Sessions []SessionReport `json:"sessions,omitempty"`
	// AdminGrants are the time-limited admin grants the agent enforces on
	// the device (#388), so the console can see an expiry enforced offline.
	// Left out when there are none.
	AdminGrants []localadmin.GrantReport `json:"admin_grants,omitempty"`
	// Capabilities lists the task features this agent supports (contract
	// v1 §6). Always sent, even empty, so the backend can tell "none" from
	// an agent too old to report them.
	Capabilities []string `json:"capabilities"`
	// local_admin_members, signed_in_users, last_signed_in_user and
	// identity_join (#223), at the top level next to local_users. A list
	// that couldn't be read is sent as null.
	shared.UserIdentity
}

// SessionReport is one session helper, as the DLP status reports it:
// sessions[].capabilities.notifications is the readiness the console reads
// (contract Compliance-OS#623).
type SessionReport struct {
	User         string            `json:"user"`
	State        string            `json:"state"`
	SessionID    string            `json:"session_id,omitempty"`
	Capabilities map[string]string `json:"capabilities,omitempty"`
}

var sessionsSource atomic.Pointer[func() []SessionReport]

// SetSessionsSource installs (or with nil removes) what fills the
// inventory's sessions.
func SetSessionsSource(f func() []SessionReport) {
	if f == nil {
		sessionsSource.Store(nil)
		return
	}
	sessionsSource.Store(&f)
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
	payload := buildPayload(sysInfo)
	if f := sessionsSource.Load(); f != nil {
		payload.Sessions = (*f)()
	}
	if cfg != nil && cfg.Path != "" {
		payload.AdminGrants = localadmin.Report(localadmin.StorePath(filepath.Dir(cfg.Path)), time.Now())
	}

	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	c := supabase.FromConfig(cfg, supabase.WithHTTPClient(s.client))
	params := map[string]interface{}{"payload": payload}
	return rpcutil.PostEnqueue(ctx, c, "agent_enqueue_inventory", params, "inventory")
}

// listOrOmit returns s as an interface, or a nil interface when s is nil.
// A nil slice stored in an interface{} field is a typed nil that omitempty
// does not drop, so it would be sent as JSON null, which the server reads
// as "the device has no value" (#387). A nil slice means the collector
// failed or timed out: leave the key out so the server keeps the last good
// value. An empty, non-nil slice (collection ran, found nothing) is still
// sent as [].
func listOrOmit[T any](s []T) interface{} {
	if s == nil {
		return nil
	}
	return s
}

// buildPayload maps the collected system info to the inventory payload.
func buildPayload(sysInfo *shared.SystemInfo) AgentUpdatePayload {
	firmware := map[string]interface{}{
		"type":    sysInfo.FirmwareType,
		"vendor":  sysInfo.FirmwareVendor,
		"version": sysInfo.FirmwareVersion,
	}
	return AgentUpdatePayload{
		Status:           "active",
		Hostname:         sysInfo.Hostname,
		ComputerName:     sysInfo.Hostname,
		CPUInfo:          sysInfo.CPUInfoDetailed,
		SerialNumber:     sysInfo.SerialNumber,
		HardwareModel:    sysInfo.HardwareModel,
		BatteryCondition: sysInfo.BatteryCondition,
		RAMS:             sysInfo.RAMs,
		LocalUsers:       listOrOmit(sysInfo.LocalUsers),
		Display:          listOrOmit(sysInfo.Displays),
		AgentVersion:     sysInfo.AgentVersion,
		FQDN:             sysInfo.FQDN,
		ChassisType:      sysInfo.ChassisType,
		KernelVersion:    sysInfo.KernelVersion,
		GPUs:             listOrOmit(sysInfo.GPUs),
		Disks:            listOrOmit(sysInfo.Disks),
		Firmware:         firmware,
		TPMVersion:       sysInfo.TPMVersion,
		NetworkAdapters:  listOrOmit(sysInfo.NetworkAdapters),
		Peripherals:      listOrOmit(sysInfo.Peripherals),
		AudioDevices:     listOrOmit(sysInfo.AudioDevices),
		Printers:         listOrOmit(sysInfo.Printers),
		OSInformation:    sysInfo.OSInformation,
		SecurityInfo:     sysInfo.SecurityInfo,
		MDM:              sysInfo.MDM,
		PowerTelemetry:   sysInfo.PowerTelemetry,
		Capabilities:     constants.Capabilities(),
		UserIdentity:     sysInfo.UserIdentity,
	}
}
