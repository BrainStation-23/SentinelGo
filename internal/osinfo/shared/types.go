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
	UserIdentity                        // local_admin_members, signed_in_users, … (#223)
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

	// PowerTelemetry summarises the window since the last successful
	// inventory upload (#198). The scheduler fills it in just before an
	// upload; it is not part of the inventory fingerprint.
	PowerTelemetry *PowerTelemetry `json:"power_telemetry,omitempty"`
}

// PowerTelemetry is the inventory payload's power_telemetry object: the
// average CPU usage over the window since the last successful upload.
// Samples counts completed sampling intervals, so Samples ×
// SampleIntervalSeconds is roughly how long the machine was awake.
//
// The rest is measured power (#199). OnACSamples counts ticks the OS
// reported AC power, and is left out when it never reported a power source
// (desktops and VMs without a battery). MeasuredSamples counts ticks with a
// real reading of the machine's draw, MeasuredWattsAvg is their average and
// MeasuredSource is where most of them came from ("battery" or
// "apple_system_power"). The measured_* fields are left out when nothing was
// measured.
type PowerTelemetry struct {
	WindowStart           string  `json:"window_start"`
	WindowEnd             string  `json:"window_end"`
	Samples               int     `json:"samples"`
	SampleIntervalSeconds int     `json:"sample_interval_seconds"`
	CPUUsageAvgPercent    float64 `json:"cpu_usage_avg_percent"`

	OnACSamples      *int    `json:"on_ac_samples,omitempty"`
	MeasuredSamples  int     `json:"measured_samples,omitempty"`
	MeasuredWattsAvg float64 `json:"measured_watts_avg,omitempty"`
	MeasuredSource   string  `json:"measured_source,omitempty"`
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
	// DiskNumber is the OS's index for the disk: the Windows disk number,
	// N in macOS diskN, or the disk's position in lsblk's list on Linux.
	DiskNumber int `json:"disk_number"`
	// Partitions lists every partition on the disk, mounted or not. It is
	// always an array (never null) so the server can expand it directly.
	Partitions []DiskPartition `json:"partitions"`
}

// DiskPartition is one partition (or, on macOS, one APFS volume) of a disk.
// Field names match sentinel-ops' agent_disk_partitions columns one-to-one.
//
// It never carries a BitLocker recovery password: KeyProtectorID is the
// RecoveryPassword protector's id, which is not secret and is how the
// console links a partition to its escrowed key.
type DiskPartition struct {
	PartitionNumber int    `json:"partition_number"`
	PartitionType   string `json:"partition_type"`         // "EFI", "MSR", "Recovery", "Basic", or the platform's type name
	DriveLetter     string `json:"drive_letter,omitempty"` // bare letter, no colon: "C"
	MountPoint      string `json:"mount_point,omitempty"`
	VolumeLabel     string `json:"volume_label,omitempty"`
	VolumeGUID      string `json:"volume_guid,omitempty"`
	FileSystem      string `json:"file_system,omitempty"`
	SizeBytes       uint64 `json:"size_bytes"`
	FreeBytes       uint64 `json:"free_bytes,omitempty"`
	IsBoot          bool   `json:"is_boot"`   // holds the running OS
	IsSystem        bool   `json:"is_system"` // EFI / boot loader partition
	// EncryptionState is full, partial, none, encrypting, decrypting or
	// unknown. unknown means the agent couldn't tell, never "not encrypted".
	EncryptionState      string   `json:"encryption_state"`
	EncryptionPercentage *float64 `json:"encryption_percentage,omitempty"`
	EncryptionProvider   string   `json:"encryption_provider,omitempty"` // BitLocker | FileVault | LUKS
	EncryptionMethod     string   `json:"encryption_method,omitempty"`
	ProtectionStatus     string   `json:"protection_status,omitempty"` // on | off | unknown
	KeyProtectorID       string   `json:"key_protector_id,omitempty"`
	KeyProtectorTypes    []string `json:"key_protector_types,omitempty"`
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

	// Compliance telemetry (#172); each is left out when it can't be read.
	// PasswordLastSet is ISO 8601 UTC.
	IsEnabled       *bool      `json:"is_enabled,omitempty"`
	LastLogon       *LastLogon `json:"last_logon,omitempty"`
	PasswordLastSet string     `json:"password_last_set,omitempty"`

	// IsBuiltin marks an account the OS creates (#223): on Windows the
	// built-in Administrator, Guest, DefaultAccount and WDAGUtilityAccount
	// (RIDs 500, 501, 503, 504), found by RID so a renamed one still counts.
	IsBuiltin bool `json:"is_builtin,omitempty"`
}

// UserIdentity is who administers and uses the device, beyond its local
// accounts (#223). A nil slice means it couldn't be read (sent as null); an
// empty one means there are none.
type UserIdentity struct {
	AdminMembers     []LocalAdminMember `json:"local_admin_members"`
	SignedInUsers    []SignedInUser     `json:"signed_in_users"`
	LastSignedInUser string             `json:"last_signed_in_user,omitempty"` // last interactive sign-in
	Join             *IdentityJoin      `json:"identity_join,omitempty"`
}

// LocalAdminMember is a member of the local administrators group: on
// Windows the Administrators group (S-1-5-32-544), on macOS admin, on Linux
// sudo, wheel and admin.
type LocalAdminMember struct {
	Name string `json:"name"` // "PC\alice", "CONTOSO\Domain Admins", "AzureAD\bob", "alice"
	SID  string `json:"sid,omitempty"`
	// Source is where the principal lives: "local", "domain" (Active
	// Directory or another directory service) or "entra" (Entra ID).
	Source string `json:"source"`
	// PrincipalClass is "user" or "group".
	PrincipalClass string `json:"principal_class"`
}

// SignedInUser is an interactive session.
type SignedInUser struct {
	Username string `json:"username"`
	Domain   string `json:"domain,omitempty"` // Windows: account domain, e.g. "AzureAD" or the computer name
	// Session is "console", "rdp" or "ssh"; "terminal" for a local terminal
	// on macOS/Linux.
	Session string `json:"session"`
	State   string `json:"state,omitempty"` // Windows: "active" or "disconnected"
	Since   string `json:"since,omitempty"` // sign-in time, ISO 8601 UTC
}

// IdentityJoin is the device's directory membership.
type IdentityJoin struct {
	Type       string `json:"type"` // "workgroup", "domain", "entra" or "hybrid"
	Domain     string `json:"domain,omitempty"`
	TenantID   string `json:"tenant_id,omitempty"`
	TenantName string `json:"tenant_name,omitempty"`
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

	// Compliance telemetry (#172), defined by the "Compliance telemetry"
	// section of sentinel-ops docs/agent-ingestion.md. Every key is optional:
	// nil means the agent could not read it, and the key is left out so the
	// server shows the matching check as unknown rather than failing.
	ScreenLock          *ScreenLockInfo     `json:"screen_lock,omitempty"`
	PasswordPolicy      *PasswordPolicyInfo `json:"password_policy,omitempty"`
	AutoLoginEnabled    *bool               `json:"auto_login_enabled,omitempty"`
	GuestAccountEnabled *bool               `json:"guest_account_enabled,omitempty"`
	RemoteAccess        *RemoteAccessInfo   `json:"remote_access,omitempty"`
	Patching            *PatchingInfo       `json:"patching,omitempty"`
	AuditLogging        *AuditLoggingInfo   `json:"audit_logging,omitempty"`
	TimeSync            *TimeSyncInfo       `json:"time_sync,omitempty"`
	Backup              *BackupInfo         `json:"backup,omitempty"`

	// AutoRun and ApplicationControl (#178) follow the same rules.
	AutoRun            *AutoRunInfo            `json:"autorun,omitempty"`
	ApplicationControl *ApplicationControlInfo `json:"application_control,omitempty"`
}

// ScreenLockInfo describes the idle screen lock. IdleTimeoutSeconds is how
// long the device sits idle before it locks.
type ScreenLockInfo struct {
	Enabled               *bool `json:"enabled,omitempty"`
	IdleTimeoutSeconds    *int  `json:"idle_timeout_seconds,omitempty"`
	RequirePasswordOnWake *bool `json:"require_password_on_wake,omitempty"`
}

// PasswordPolicyInfo is the local account password policy. MaxAgeDays,
// History and LockoutThreshold use 0 for "none" (never expires, no history,
// never locks out).
type PasswordPolicyInfo struct {
	MinLength        *int  `json:"min_length,omitempty"`
	Complexity       *bool `json:"complexity,omitempty"`
	MaxAgeDays       *int  `json:"max_age_days,omitempty"`
	History          *int  `json:"history,omitempty"`
	LockoutThreshold *int  `json:"lockout_threshold,omitempty"`
}

// RemoteAccessInfo reports which remote-access services accept connections.
type RemoteAccessInfo struct {
	RDPEnabled           *bool `json:"rdp_enabled,omitempty"`
	RDPNLARequired       *bool `json:"rdp_nla_required,omitempty"`
	SMB1Enabled          *bool `json:"smb1_enabled,omitempty"`
	SSHEnabled           *bool `json:"ssh_enabled,omitempty"`
	ScreenSharingEnabled *bool `json:"screen_sharing_enabled,omitempty"`
}

// PatchingInfo reports OS update state. LastUpdateInstalledAt is ISO 8601
// UTC. MissingUpdates is a pointer so that "checked, none missing" ([]) and
// "could not check" (key left out) stay distinct.
type PatchingInfo struct {
	LastUpdateInstalledAt string           `json:"last_update_installed_at,omitempty"`
	PendingReboot         *bool            `json:"pending_reboot,omitempty"`
	AutoUpdateEnabled     *bool            `json:"auto_update_enabled,omitempty"`
	MissingUpdates        *[]MissingUpdate `json:"missing_updates,omitempty"`
}

// MissingUpdate is one available update that is not installed.
type MissingUpdate struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// AuditLoggingInfo reports whether security auditing is on and what it covers.
type AuditLoggingInfo struct {
	Enabled      *bool    `json:"enabled,omitempty"`
	Categories   []string `json:"categories,omitempty"`
	LogMaxSizeMB *int     `json:"log_max_size_mb,omitempty"`
}

// TimeSyncInfo reports network time synchronisation. OffsetMS is the clock's
// offset from the time source; it changes every reading, so the scheduler's
// change fingerprint ignores it.
type TimeSyncInfo struct {
	Enabled  *bool  `json:"enabled,omitempty"`
	Source   string `json:"source,omitempty"`
	OffsetMS *int64 `json:"offset_ms,omitempty"`
}

// BackupInfo reports the backup product found on the device.
// LastSuccessAt is ISO 8601 UTC.
type BackupInfo struct {
	Product       string `json:"product,omitempty"`
	Enabled       *bool  `json:"enabled,omitempty"`
	LastSuccessAt string `json:"last_success_at,omitempty"`
}

// AutoRunInfo reports whether removable and network media can start
// programs on their own (AutoRun, autorun.inf) and whether Windows offers to
// open them (AutoPlay). Windows only.
type AutoRunInfo struct {
	AutoRunDisabled  *bool `json:"autorun_disabled,omitempty"`
	AutoPlayDisabled *bool `json:"autoplay_disabled,omitempty"`
}

// Application control products and modes reported in ApplicationControlInfo.
const (
	AppControlWDAC       = "WDAC"
	AppControlAppLocker  = "AppLocker"
	AppControlGatekeeper = "Gatekeeper"
	AppControlFapolicyd  = "fapolicyd"

	AppControlEnforced = "enforced"
	AppControlAudit    = "audit"
	AppControlOff      = "off"
)

// ApplicationControlInfo reports the strongest application allow-listing
// product on the device and its mode (enforced, audit or off).
type ApplicationControlInfo struct {
	Product string `json:"product"`
	Mode    string `json:"mode"`
}

// 1. Firewall Security
type FirewallSecurityInfo struct {
	FirewallState  string            `json:"firewall_state"` // "Enabled", "Disabled", "Partially Enabled"
	ActiveProfiles []string          `json:"active_profiles"`
	Profiles       []FirewallProfile `json:"profiles"`
	// NetworkProfiles is the firewall profile in force on each connected
	// network (Windows only).
	NetworkProfiles []NetworkFirewallProfile `json:"network_profiles,omitempty"`
}

// NetworkFirewallProfile is the Windows firewall profile a connected network
// uses.
type NetworkFirewallProfile struct {
	Interface string `json:"interface"`
	Profile   string `json:"profile"` // "Domain", "Private" or "Public"
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
	SSHRootLogin    string `json:"ssh_root_login,omitempty"`    // "Enabled", "Disabled", "Unknown", "Not installed"
	SSHPasswordAuth string `json:"ssh_password_auth,omitempty"` // "Enabled", "Disabled", "Unknown", "Not installed"
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
	OpenAdministrativePorts []uint16 `json:"open_administrative_ports"` // ports of RiskyServices, sorted

	// RiskyServices are the commonly attacked services (SMB, RDP, SSH,
	// databases, …) listening on a non-loopback address, one per socket,
	// with whether the host firewall lets them be reached (#221).
	RiskyServices []RiskyService `json:"risky_services"`

	// Linux Specific SSH
	SSHRootLoginStatus    string `json:"ssh_root_login_status,omitempty"`    // "Enabled", "Disabled", "Unknown", "Not installed"
	SSHPasswordAuthStatus string `json:"ssh_password_auth_status,omitempty"` // "Enabled", "Disabled", "Unknown", "Not installed"
	SSHKeyAuthStatus      string `json:"ssh_key_auth_status,omitempty"`      // "Enabled", "Disabled", "Unknown", "Not installed"
}

// RiskyService is a commonly attacked service listening on the network.
type RiskyService struct {
	Name        string `json:"name"` // "SMB", "RDP", "SSH", …
	Port        uint16 `json:"port"`
	Protocol    string `json:"protocol"` // "tcp" or "udp"
	Address     string `json:"address"`
	Scope       string `json:"scope"` // "all" (wildcard bind), "interface" or "unknown"
	ProcessName string `json:"process_name"`
	// Firewall is whether the host firewall lets inbound connections reach
	// it: "allowed", "blocked", "disabled" (no firewall filtering) or
	// "unknown".
	Firewall string `json:"firewall"`
	// ReachableProfiles are the active Windows firewall profiles that let
	// connections in (Windows only).
	ReachableProfiles []string `json:"reachable_profiles,omitempty"`
	// RemoteScope is the widest set of remote addresses an allow rule lets
	// in: "any", "local_subnet", "specific" or "unknown". "any" when the
	// firewall is "disabled"; empty unless Firewall is "allowed" or
	// "disabled" (#251).
	RemoteScope string `json:"remote_scope,omitempty"`
	// RemoteAddresses lists the allowed remote ranges when RemoteScope is
	// "specific" (at most 10), e.g. ["10.10.0.0/16", "Intranet"].
	RemoteAddresses []string `json:"remote_addresses,omitempty"`
	// OnPublicAddress: the socket is bound to a public unicast address (not
	// private, ULA, CGNAT, link-local or special-use), or it's a wildcard
	// socket and the host has one of a family it accepts; when the firewall
	// lets connections in only on some interfaces, on one of those.
	OnPublicAddress bool `json:"on_public_address,omitempty"`
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
	NetworkExposureLevel     string   `json:"network_exposure_level"`     // "Low", "Medium", "High", "Critical"
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
