package shared

import "time"

type SystemInfo struct {
	Timestamp        time.Time          `json:"timestamp"`
	Hostname         string             `json:"hostname"`
	Uptime           uint64             `json:"uptime"`
	CPU              CPUInfo            `json:"cpu"`
	Memory           MemoryInfo         `json:"memory"`
	Disk             DiskInfo           `json:"disk"`
	Network          []NetInfo          `json:"network"`
	MACAddress       string             `json:"mac_address"`
	SerialNumber     string             `json:"serial_number"`
	HardwareModel    string             `json:"hardware_model"`
	OSQueryVersion   string             `json:"osquery_version"`
	BatteryCondition string             `json:"battery_condition"`
	LocalUsers       []UserWithGroup    `json:"local_users"`
	LastRestart      string             `json:"last_restart"`
	AgentVersion     string             `json:"agent_version"`
	FQDN             string             `json:"fqdn"`
	ChassisType      string             `json:"chassis_type"`
	KernelVersion    string             `json:"kernel_version"`
	GPUs             []GPU              `json:"gpus"`
	RAMs             RAMInfo            `json:"rams"`
	Disks            []DiskDevice       `json:"disks"`
	FirmwareType     string             `json:"firmware_type"`
	FirmwareVendor   string             `json:"firmware_vendor"`
	FirmwareVersion  string             `json:"firmware_version"`
	TPMVersion       string             `json:"tpm_version"`
	NetworkAdapters  []NetAdapter       `json:"network_adapters"`
	Peripherals      []PeripheralDevice `json:"peripherals"`
	Displays         []Display          `json:"display"`
	CPUInfoDetailed  CPUInfoDetailed    `json:"cpu_info_detailed"`
	AudioDevices     []AudioDevice      `json:"audio_devices"`
	Printers         []Printer          `json:"printers"`
	OSInformation    OSInformation      `json:"os_information"`
	SecurityInfo     SecurityInfo       `json:"security_info"`
}

type CPUInfo struct {
	ModelName string  `json:"model_name"`
	Cores     int     `json:"cores"`
	Usage     float64 `json:"usage_percent"`
}

type CPUInfoDetailed struct {
	Processor          string `json:"processor"`
	ClockSpeed         string `json:"clock_speed"`
	NumberCores        int    `json:"number_cores"`
	NumberLogicalCores int    `json:"number_logical_cores"`
	ArchitectureType   string `json:"architecture_type"`
	Manufacturer       string `json:"manufacturer"`
}

type MemoryInfo struct {
	Total uint64  `json:"total"`
	Used  uint64  `json:"used"`
	Free  uint64  `json:"free"`
	Usage float64 `json:"usage_percent"`
}

type DiskInfo struct {
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
	Free  uint64 `json:"free"`
}

type NetInfo struct {
	Name      string `json:"name"`
	BytesSent uint64 `json:"bytes_sent"`
	BytesRecv uint64 `json:"bytes_recv"`
	MACAddr   string `json:"mac_address"`
}

type DiskDevice struct {
	FreeCapacity     uint64 `json:"free_capacity"`
	Description      string `json:"description"`
	Type             string `json:"type"`
	Capacity         uint64 `json:"capacity"`
	EncryptionStatus string `json:"encryption_status"`
	EncryptionType   string `json:"encryption_type"`
	SerialNumber     string `json:"serial_number"`
	Manufacturer     string `json:"manufacturer"`
	DriveLetter      string `json:"drive_letter,omitempty"`
	DriveType        string `json:"drive_type"`
	HealthStatus     string `json:"health_status"`
	InterfaceType    string `json:"interface_type"`
	FileSystem       string `json:"file_system,omitempty"`
	MountPoint       string `json:"mount_point,omitempty"`
}

type OSLastBootTime struct {
	Relative string `json:"relative"`
	DateTime string `json:"datetime"`
}

type OSInformation struct {
	OSName                  string         `json:"os_name"`
	OSVersion               string         `json:"os_version"`
	OSType                  string         `json:"os_type"`
	OSServicePack           string         `json:"os_service_pack"`
	Architecture            string         `json:"architecture"`
	OSPlatform              string         `json:"os_platform"`
	OSLocale                string         `json:"os_locale,omitempty"`
	OSLanguage              string         `json:"os_language,omitempty"`
	OSTimeZone              string         `json:"os_time_zone"`
	OSTimeZoneOffsetMinutes int            `json:"os_time_zone_offset_minutes"`
	OSLastBootTime          OSLastBootTime `json:"os_last_boot_time"`
}

type RAMStick struct {
	Name             string `json:"name"`
	Capacity         uint64 `json:"capacity"`
	ArchitectureType string `json:"architecture_type"`
	Manufacturer     string `json:"manufacturer"`
	ClockSpeedMHz    int    `json:"clock_speed_mhz"`
	Serial           string `json:"serial,omitempty"`
	FormFactor       string `json:"form_factor,omitempty"`
	Slot             string `json:"slot,omitempty"`
}

type RAMInfo struct {
	TotalCapacity uint64     `json:"total_capacity"`
	RAMs          []RAMStick `json:"rams"`
}

type Display struct {
	Description    string   `json:"description"`
	Manufacturer   string   `json:"manufacturer"`
	SerialNumber   string   `json:"serial"`
	Model          string   `json:"model"`
	Size           float64  `json:"display_size,omitempty"`
	RefreshRate    float64  `json:"refresh_rate,omitempty"`
	Year           int      `json:"year,omitempty"`
	MonitorType    []string `json:"monitorType,omitempty"`
	ConnectionType string   `json:"connectionType,omitempty"`
	Resolution     string   `json:"resolution,omitempty"`
}

type GPU struct {
	Name          string `json:"name"`
	Manufacturer  string `json:"manufacturer"`
	Architecture  string `json:"architecture"`
	Chipset       string `json:"chipset"`
	DedicatedVRAM string `json:"dedicated_vram"`
	SharedVRAM    string `json:"shared_vram"`
	DriverVersion string `json:"driver_version"`
	DriverDate    string `json:"driver_date"`
	HardwareID    string `json:"hardware_id"`
	BIOSVersion   string `json:"bios_version,omitempty"`
	CurrentStatus string `json:"current_status"`
}

type NetAdapterIPv4 struct {
	Address    string `json:"address"`
	Subnet     string `json:"subnet"`
	SubnetMask string `json:"subnet_mask"`
}

type NetAdapterIPv6 struct {
	Address    string `json:"address"`
	Subnet     string `json:"subnet"`
	SubnetMask string `json:"subnet_mask"`
}

type NetAdapter struct {
	Type           string         `json:"type"`
	ConnectionName string         `json:"connection_name"`
	Description    string         `json:"description"`
	Manufacturer   string         `json:"manufacturer"`
	MACAddress     string         `json:"mac_address"`
	IPv4           NetAdapterIPv4 `json:"ipv4,omitempty"`
	IPv6           NetAdapterIPv6 `json:"ipv6,omitempty"`
	IsConnected    bool           `json:"is_connected"`
}

type AudioDevice struct {
	Description  string `json:"description"`
	Manufacturer string `json:"manufacturer"`
	Type         string `json:"type,omitempty"` // "input", "output", "input/output"
}

type PrintingResolution struct {
	HorizontalDPI int `json:"horizontal_dpi"`
	VerticalDPI   int `json:"vertical_dpi"`
}

type Printer struct {
	Description        string             `json:"description"`
	LocationType       string             `json:"location_type"`
	PrintingType       string             `json:"printing_type"`
	PrintingResolution PrintingResolution `json:"printing_resolution"`
	MarkingType        string             `json:"marking_type"`
}

type PeripheralDevice struct {
	Type           string `json:"type"`
	Description    string `json:"description"`
	Manufacturer   string `json:"manufacturer"`
	Model          string `json:"model,omitempty"`
	SerialNumber   string `json:"serial_number,omitempty"`
	VendorID       string `json:"vendor_id,omitempty"`
	ProductID      string `json:"product_id,omitempty"`
	Version        string `json:"version,omitempty"`
	Location       string `json:"location,omitempty"`
	ConnectionType string `json:"connection_type,omitempty"`
	IsBuiltIn      bool   `json:"is_built_in,omitempty"`
	Status         string `json:"status,omitempty"`
}

type UserWithGroup struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups,omitempty"`
	UID      string   `json:"uid,omitempty"`
	GID      string   `json:"gid,omitempty"`
	HomeDir  string   `json:"home_dir,omitempty"`
	Shell    string   `json:"shell,omitempty"`
}

// SecurityInfo aggregates all collected security telemetry.
type SecurityInfo struct {
	AntivirusProducts []AntivirusProduct `json:"antivirus_products"`
	FirewallEnabled   bool               `json:"firewall_enabled"`
	FirewallProfiles  []FirewallProfile  `json:"firewall_profiles"`
	CoreIsolation     CoreIsolationInfo  `json:"core_isolation"`
	SecureBootEnabled string             `json:"secure_boot_enabled"`
	ListeningPorts    []ListeningPort    `json:"listening_ports"`
}

// AntivirusProduct describes a single detected endpoint-protection product.
type AntivirusProduct struct {
	Name     string `json:"name"`
	Enabled  string `json:"enabled"`    // "enabled", "disabled", "unknown"
	UpToDate string `json:"up_to_date"` // "yes", "no", "unknown"
	Source   string `json:"source"`     // "SecurityCenter2", "service", "process", "gatekeeper"
}

// FirewallProfile describes one firewall zone or policy profile.
type FirewallProfile struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// CoreIsolationInfo holds platform-hardening feature states.
// Fields irrelevant to the host platform are zero-valued.
type CoreIsolationInfo struct {
	MemoryIntegrityEnabled bool   `json:"memory_integrity_enabled"` // Windows: HVCI
	VBSEnabled             bool   `json:"vbs_enabled"`              // Windows: Virtualization-Based Security
	CredentialGuardEnabled bool   `json:"credential_guard_enabled"` // Windows: Credential Guard
	SIPEnabled             string `json:"sip_enabled"`              // macOS: System Integrity Protection
	SELinuxMode            string `json:"se_linux_mode"`            // Linux: "enforcing"/"permissive"/"disabled"/"unknown"
	AppArmorEnabled        bool   `json:"app_armor_enabled"`        // Linux: AppArmor
	KernelLockdown         string `json:"kernel_lockdown"`          // Linux: "none"/"integrity"/"confidentiality"/"unknown"
}

// ListeningPort describes a single port the host is listening on.
type ListeningPort struct {
	Protocol    string `json:"protocol"` // "tcp" or "udp"
	Port        uint16 `json:"port"`
	Address     string `json:"address"`      // bound address, e.g. "0.0.0.0" or "127.0.0.1"
	ProcessName string `json:"process_name"` // best-effort; empty if lookup fails
	ProcessID   int32  `json:"process_id"`
}
