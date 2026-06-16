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

type IPv4Address struct {
	Address    string `json:"address"`
	Subnet     string `json:"subnet"`
	SubnetMask string `json:"subnet_mask"`
	IsDHCP     bool   `json:"is_dhcp"`
}

type IPv6Address struct {
	Address   string `json:"address"`
	PrefixLen int    `json:"prefix_len"`
}

type WiFiInfo struct {
	SSID           string `json:"ssid"`
	SignalStrength int    `json:"signal_strength_dbm"`
	FrequencyBand  string `json:"frequency_band"`
}

type NetAdapter struct {
	InterfaceName  string        `json:"interface_name"`
	FriendlyName   string        `json:"friendly_name"`
	DeviceName     string        `json:"device_name,omitempty"`
	AdapterType    string        `json:"adapter_type"`
	Status         string        `json:"status"`
	IsConnected    bool          `json:"is_connected"`
	MACAddress     string        `json:"mac_address"`
	Manufacturer   string        `json:"manufacturer"`
	SpeedMbps      int64         `json:"speed_mbps"`
	IPv4Addresses  []IPv4Address `json:"ipv4_addresses,omitempty"`
	IPv6Addresses  []IPv6Address `json:"ipv6_addresses,omitempty"`
	DefaultGateway string        `json:"default_gateway,omitempty"`
	DNSServers     []string      `json:"dns_servers,omitempty"`
	WiFi           *WiFiInfo     `json:"wifi,omitempty"`
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
	AntivirusProducts     []AntivirusProduct `json:"antivirus_products"`
	FirewallEnabled       bool               `json:"firewall_enabled"`
	FirewallProfiles      []FirewallProfile  `json:"firewall_profiles"`
	CoreIsolation         CoreIsolationInfo  `json:"core_isolation"`
	SecureBootEnabled     string             `json:"secure_boot_enabled"`
	ListeningPorts        []ListeningPort    `json:"listening_ports"`
	USBMassStorageEnabled string             `json:"usb_mass_storage_enabled"` // "enabled", "disabled", "unknown"

	// Category-Wise Security Modules (New)
	FirewallSecurity      FirewallSecurityInfo      `json:"firewall_security"`
	AntivirusProtection   AntivirusProtectionInfo   `json:"antivirus_protection"`
	EDRXDRDetection       EDRXDRDetectionInfo       `json:"edr_xdr_detection"`
	KernelHardening       KernelHardeningInfo       `json:"kernel_hardening"`
	DeviceEncryption      DeviceEncryptionInfo      `json:"device_encryption"`
	HardwareSecurity      HardwareSecurityInfo      `json:"hardware_security"`
	IdentityAccessControl IdentityAccessControlInfo `json:"identity_access_control"`
	NetworkExposureAccess NetworkExposureAccessInfo `json:"network_exposure_access"`
	PostureSummary        SecurityPostureSummary    `json:"posture_summary"`
}

// 1. Firewall Security
type FirewallSecurityInfo struct {
	FirewallState  string            `json:"firewall_state"` // "Enabled", "Disabled", "Partially Enabled"
	ActiveProfiles []string          `json:"active_profiles"`
	Profiles       []FirewallProfile `json:"profiles"`
}

// 2. Antivirus Protection
type AntivirusProtectionInfo struct {
	Products []AntivirusDetails `json:"products"`

	// Windows Specific Windows Defender / Endpoint Protection controls
	WindowsDefenderDetails *WindowsDefenderDetails `json:"windows_defender_details,omitempty"`

	// macOS Specific Built-in
	XProtectVersion string `json:"xprotect_version,omitempty"`
	MRTInstalled    bool   `json:"mrt_installed,omitempty"`
}

type AntivirusDetails struct {
	ProductName             string            `json:"product_name"`
	Vendor                  string            `json:"vendor"`
	Version                 string            `json:"version"`
	EngineVersion           string            `json:"engine_version,omitempty"`
	SignatureVersion        string            `json:"signature_version,omitempty"`
	RealTimeProtectionState string            `json:"real_time_protection_state"` // "Enabled", "Disabled", "Unknown"
	ServiceStatus           string            `json:"service_status"`             // "Running", "Stopped", "Disabled", "Unknown"
	UpdateStatus            string            `json:"update_status"`              // "Up to Date", "Out of Date", "Unknown"
	LastUpdateTime          string            `json:"last_update_time,omitempty"`
	ScanInfo                *SecurityScanInfo `json:"scan_info,omitempty"`
}

type WindowsDefenderDetails struct {
	RealTimeProtectionEnabled bool              `json:"real_time_protection_enabled"`
	SmartScreenEnabled        bool              `json:"smart_screen_enabled"`
	ControlledFolderAccess    bool              `json:"controlled_folder_access"`
	TamperProtectionEnabled   bool              `json:"tamper_protection_enabled"`
	ASRRulesCount             int               `json:"asr_rules_count"`
	SignatureLastUpdated      string            `json:"signature_last_updated"`
	ScanInfo                  *SecurityScanInfo `json:"scan_info,omitempty"`
}

type SecurityScanInfo struct {
	LastScanTime      string          `json:"last_scan_time"`      // Timestamp or "Unknown"
	ScanType          string          `json:"scan_type"`           // "Quick Scan", "Full Scan", "On-Access", "Unknown"
	ScanResult        string          `json:"scan_result"`         // "Clean", "Threats Detected", "Unknown"
	ScannedFilesCount int64           `json:"scanned_files_count"` // Files scanned if available, otherwise 0
	RecentThreats     []ThreatDetails `json:"recent_threats"`
}

type ThreatDetails struct {
	ThreatName    string `json:"threat_name"`
	Severity      string `json:"severity"` // "Low", "Medium", "High", "Critical", "Unknown"
	FilePath      string `json:"file_path"`
	ActionTaken   string `json:"action_taken"` // "Quarantined", "Removed", "Allowed", "Blocked", "Pending"
	DetectionTime string `json:"detection_time"`
}

// 3. EDR / XDR Detection
type EDRXDRDetectionInfo struct {
	Agents []EDRXDRAgentDetails `json:"agents"`
}

type EDRXDRAgentDetails struct {
	AgentName              string `json:"agent_name"`
	Vendor                 string `json:"vendor"`
	AgentVersion           string `json:"agent_version"`
	SensorVersion          string `json:"sensor_version,omitempty"`
	ServiceStatus          string `json:"service_status"` // "Running", "Stopped", "Disabled", "Unknown"
	HealthStatus           string `json:"health_status"`  // "Healthy", "Unhealthy", "Unknown"
	LastCheckIn            string `json:"last_check_in,omitempty"`
	ConnectivityStatus     string `json:"connectivity_status"`      // "Connected", "Disconnected", "Unknown"
	TamperProtectionStatus string `json:"tamper_protection_status"` // "Enabled", "Disabled", "Unknown"

	// Section 9: Agent Health Flags
	Installed         bool `json:"installed"`
	Running           bool `json:"running"`
	Stopped           bool `json:"stopped"`
	Disabled          bool `json:"disabled"`
	Offline           bool `json:"offline"`
	Healthy           bool `json:"healthy"`
	Unhealthy         bool `json:"unhealthy"`
	Tampered          bool `json:"tampered"`
	CloudConnected    bool `json:"cloud_connected"`
	CloudDisconnected bool `json:"cloud_disconnected"`
}

// 4. Kernel & OS Hardening
type KernelHardeningInfo struct {
	MemoryIntegrityEnabled bool   `json:"memory_integrity_enabled"` // HVCI (Windows)
	VBSEnabled             bool   `json:"vbs_enabled"`              // VBS (Windows)
	SIPEnabled             string `json:"sip_enabled"`              // SIP (macOS)
	SELinuxMode            string `json:"se_linux_mode"`            // SELinux (Linux)
	AppArmorEnabled        bool   `json:"app_armor_enabled"`        // AppArmor (Linux)
	KernelLockdown         string `json:"kernel_lockdown"`          // Lockdown (Linux)
	USBMassStorageEnabled  string `json:"usb_mass_storage_enabled"` // USB storage blocking status
}

// 5. Device Encryption
type DeviceEncryptionInfo struct {
	EncryptionStatus        string `json:"encryption_status"`          // "Encrypted", "Unencrypted", "Partially Encrypted", "Unknown"
	ProtectionStatus        string `json:"protection_status"`          // "Enabled", "Disabled", "Unknown"
	RecoveryKeyBackupStatus string `json:"recovery_key_backup_status"` // "Backed Up", "Not Backed Up", "Unknown"
	EncryptionProvider      string `json:"encryption_provider"`        // "BitLocker", "FileVault", "LUKS", "None", "Unknown"
}

// 6. Hardware Security
type HardwareSecurityInfo struct {
	TPMStatus            string `json:"tpm_status"`             // "Enabled", "Disabled", "Unsupported", "Unknown"
	TPMVersion           string `json:"tpm_version"`            // e.g. "2.0", "1.2", "None", "Unknown"
	SecureBootStatus     string `json:"secure_boot_status"`     // "Enabled", "Disabled", "Unsupported", "Unknown"
	SecureEnclaveStatus  string `json:"secure_enclave_status"`  // "Enabled", "Disabled", "Unsupported", "Unknown" (macOS)
	ActivationLockStatus string `json:"activation_lock_status"` // "Enabled", "Disabled", "Unsupported", "Unknown" (macOS)
}

// 7. Identity & Access Control
type IdentityAccessControlInfo struct {
	// Windows
	WindowsHelloStatus    string `json:"windows_hello_status,omitempty"`    // "Enabled", "Disabled", "Unknown"
	CredentialGuardStatus string `json:"credential_guard_status,omitempty"` // "Enabled", "Disabled", "Unknown"
	DeviceGuardStatus     string `json:"device_guard_status,omitempty"`     // "Enabled", "Disabled", "Unknown"
	UACStatus             string `json:"uac_status,omitempty"`              // "Enabled", "Disabled", "Unknown"

	// macOS
	SecureTokenStatus    string `json:"secure_token_status,omitempty"`    // "Enabled", "Disabled", "Unknown"
	BootstrapTokenStatus string `json:"bootstrap_token_status,omitempty"` // "Enabled", "Disabled", "Unknown"
	TouchIDStatus        string `json:"touch_id_status,omitempty"`        // "Enabled", "Disabled", "Unknown"

	// Linux
	SSHRootLogin    string `json:"ssh_root_login,omitempty"`    // "Enabled", "Disabled", "Unknown"
	SSHPasswordAuth string `json:"ssh_password_auth,omitempty"` // "Enabled", "Disabled", "Unknown"
	SudoPrivilege   string `json:"sudo_privilege,omitempty"`    // "Configured", "Misconfigured", "Disabled", "Unknown"

	// Patch & Update Compliance (New)
	PatchComplianceStatus  string `json:"patch_compliance_status"`                   // "Compliant", "Non-Compliant", "Unknown"
	CriticalKBsMissing     int    `json:"critical_kbs_missing,omitempty"`            // Windows specific
	RapidSecurityResponses string `json:"rapid_security_responses_status,omitempty"` // macOS specific ("Up to Date", "Out of Date", "Unknown")
	PendingSecurityPatches int    `json:"pending_security_patches,omitempty"`        // Linux specific
}

// 8. Network Exposure & Access
type NetworkExposureAccessInfo struct {
	TotalListeningPorts     int      `json:"total_listening_ports"`
	PubliclyBoundPorts      int      `json:"publicly_bound_ports"`
	ActiveNetworkServices   []string `json:"active_network_services"`
	RemoteAccessServices    []string `json:"remote_access_services"`
	OpenAdministrativePorts []uint16 `json:"open_administrative_ports"`

	// Linux Specific SSH
	SSHRootLoginStatus    string `json:"ssh_root_login_status,omitempty"`    // "Enabled", "Disabled", "Unknown"
	SSHPasswordAuthStatus string `json:"ssh_password_auth_status,omitempty"` // "Enabled", "Disabled", "Unknown"
	SSHKeyAuthStatus      string `json:"ssh_key_auth_status,omitempty"`      // "Enabled", "Disabled", "Unknown"
}

// 9. Security Posture Summary
type SecurityPostureSummary struct {
	OverallScore             string   `json:"overall_score"`              // "Excellent", "Good", "Fair", "Poor"
	EndpointProtectionStatus string   `json:"endpoint_protection_status"` // "Protected", "At Risk", "Unknown"
	AntivirusHealth          string   `json:"antivirus_health"`           // "Healthy", "Unhealthy", "None"
	EDRXDRHealth             string   `json:"edr_xdr_health"`             // "Healthy", "Unhealthy", "None"
	FirewallStatus           string   `json:"firewall_status"`            // "Enabled", "Disabled", "Partially Enabled"
	EncryptionStatus         string   `json:"encryption_status"`          // "Encrypted", "Unencrypted", "Partially Encrypted"
	HardwareSecurityControls string   `json:"hardware_security_controls"` // "Strong", "Weak", "Unsupported"
	IdentitySecurityControls string   `json:"identity_security_controls"` // "Configured", "At Risk"
	NetworkExposureLevel     string   `json:"network_exposure_level"`     // "Low", "Medium", "High"
	Recommendations          []string `json:"recommendations"`
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
