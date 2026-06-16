package security

import (
	"encoding/json"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

func TestParseNetshFirewall(t *testing.T) {
	input := `
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON

Public Profile Settings:
----------------------------------------------------------------------
State                                 OFF
`
	profiles := parseNetshFirewall(input)
	if len(profiles) != 3 {
		t.Fatalf("expected 3 profiles, got %d", len(profiles))
	}
	cases := []struct {
		name    string
		enabled bool
	}{
		{"Domain", true},
		{"Private", true},
		{"Public", false},
	}
	for i, c := range cases {
		if profiles[i].Name != c.name {
			t.Errorf("profile[%d]: got name %q, want %q", i, profiles[i].Name, c.name)
		}
		if profiles[i].Enabled != c.enabled {
			t.Errorf("profile[%d] %q: got enabled=%v, want %v", i, c.name, profiles[i].Enabled, c.enabled)
		}
	}
}

func TestParseNetshFirewallAllOff(t *testing.T) {
	input := `
Domain Profile Settings:
State                                 OFF

Private Profile Settings:
State                                 OFF

Public Profile Settings:
State                                 OFF
`
	profiles := parseNetshFirewall(input)
	for _, p := range profiles {
		if p.Enabled {
			t.Errorf("profile %q should be disabled", p.Name)
		}
	}
}

func TestParseRegDWORD(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		valueName string
		want      int
	}{
		{
			name: "hex value 1",
			input: `
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State
    UEFISecureBootEnabled    REG_DWORD    0x1
`,
			valueName: "UEFISecureBootEnabled",
			want:      1,
		},
		{
			name: "hex value 0",
			input: `
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard
    EnableVirtualizationBasedSecurity    REG_DWORD    0x0
`,
			valueName: "EnableVirtualizationBasedSecurity",
			want:      0,
		},
		{
			name:      "key not found",
			input:     "ERROR: The system was unable to find the specified registry key or value.",
			valueName: "Enabled",
			want:      -1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseRegDWORD(c.input, c.valueName)
			if got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}

func TestUsbStorStartToState(t *testing.T) {
	cases := []struct {
		v    int
		want string
	}{
		{4, "disabled"}, // SERVICE_DISABLED — Group Policy / MDM enforcement
		{3, "enabled"},  // SERVICE_DEMAND_START
		{2, "enabled"},  // SERVICE_AUTO_START
		{1, "enabled"},  // SERVICE_SYSTEM_START
		{0, "enabled"},  // SERVICE_BOOT_START
		{-1, "unknown"}, // parseRegDWORD sentinel for missing key
		{5, "unknown"},  // unexpected value
	}
	for _, c := range cases {
		got := usbStorStartToState(c.v)
		if got != c.want {
			t.Errorf("usbStorStartToState(%d) = %q, want %q", c.v, got, c.want)
		}
	}
}

func TestParseAVProductsJSON(t *testing.T) {
	t.Run("array with one enabled product", func(t *testing.T) {
		// productState 397568 = 0x61100: bits 12-15 = 1 (enabled), bits 4-7 = 0 (up-to-date)
		input := `[{"displayName":"Windows Defender","productState":397568}]`
		products := parseAVProductsJSON(input)
		if len(products) != 1 {
			t.Fatalf("expected 1 product, got %d", len(products))
		}
		if products[0].Name != "Windows Defender" {
			t.Errorf("got name %q", products[0].Name)
		}
		if products[0].Enabled != "enabled" {
			t.Errorf("got enabled=%q, want enabled", products[0].Enabled)
		}
		if products[0].UpToDate != "yes" {
			t.Errorf("got up_to_date=%q, want yes", products[0].UpToDate)
		}
		if products[0].Source != "SecurityCenter2" {
			t.Errorf("got source=%q", products[0].Source)
		}
	})

	t.Run("single object (not array)", func(t *testing.T) {
		input := `{"displayName":"Malwarebytes","productState":266240}`
		products := parseAVProductsJSON(input)
		if len(products) != 1 {
			t.Fatalf("expected 1 product, got %d", len(products))
		}
		if products[0].Name != "Malwarebytes" {
			t.Errorf("got name %q", products[0].Name)
		}
	})

	t.Run("multiple products", func(t *testing.T) {
		input := `[{"displayName":"Windows Defender","productState":397568},{"displayName":"Malwarebytes","productState":266240}]`
		products := parseAVProductsJSON(input)
		if len(products) != 2 {
			t.Fatalf("expected 2 products, got %d", len(products))
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		products := parseAVProductsJSON("{not json}")
		if products != nil {
			t.Errorf("expected nil for invalid JSON, got %v", products)
		}
	})

	t.Run("empty string", func(t *testing.T) {
		products := parseAVProductsJSON("")
		if products != nil {
			t.Errorf("expected nil for empty string, got %v", products)
		}
	})
}

func TestCollectFirewallSecurity(t *testing.T) {
	cases := []struct {
		name     string
		profiles []shared.FirewallProfile
		want     string
	}{
		{
			name: "all enabled",
			profiles: []shared.FirewallProfile{
				{Name: "Domain", Enabled: true},
				{Name: "Private", Enabled: true},
			},
			want: "Enabled",
		},
		{
			name: "partially enabled",
			profiles: []shared.FirewallProfile{
				{Name: "Domain", Enabled: true},
				{Name: "Private", Enabled: false},
			},
			want: "Partially Enabled",
		},
		{
			name: "all disabled",
			profiles: []shared.FirewallProfile{
				{Name: "Domain", Enabled: false},
				{Name: "Private", Enabled: false},
			},
			want: "Disabled",
		},
		{
			name:     "empty profiles",
			profiles: []shared.FirewallProfile{},
			want:     "Disabled",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := collectFirewallSecurity(c.profiles)
			if got.FirewallState != c.want {
				t.Errorf("got %q, want %q", got.FirewallState, c.want)
			}
		})
	}
}

func TestParseRegSZ(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		valueName string
		want      string
	}{
		{
			name: "standard string value",
			input: `
HKEY_LOCAL_MACHINE\SOFTWARE\CrowdStrike\Falcon
    version    REG_SZ    6.40.12345.0
`,
			valueName: "version",
			want:      "6.40.12345.0",
		},
		{
			name:      "value not found",
			input:     "ERROR: The system was unable to find the specified registry key or value.",
			valueName: "version",
			want:      "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseRegSZ(c.input, c.valueName)
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestAnalyzeNetworkExposure(t *testing.T) {
	ports := []shared.ListeningPort{
		{Protocol: "tcp", Port: 22, Address: "0.0.0.0", ProcessName: "sshd"},
		{Protocol: "tcp", Port: 3389, Address: "127.0.0.1", ProcessName: "termservice"},
		{Protocol: "tcp", Port: 8080, Address: "192.168.1.50", ProcessName: "node"},
		{Protocol: "tcp", Port: 5900, Address: "0.0.0.0", ProcessName: "vncserver"},
	}

	info := analyzeNetworkExposure(ports)
	if info.TotalListeningPorts != 4 {
		t.Errorf("expected 4 listening ports, got %d", info.TotalListeningPorts)
	}
	if info.PubliclyBoundPorts != 3 { // 22 (0.0.0.0), 8080 (192.168.1.50), 5900 (0.0.0.0)
		t.Errorf("expected 3 publicly bound ports, got %d", info.PubliclyBoundPorts)
	}
	if len(info.ActiveNetworkServices) != 4 {
		t.Errorf("expected 4 active network services, got %d", len(info.ActiveNetworkServices))
	}

	// Remote access detection: sshd (22), termservice (3389), vncserver (5900)
	if len(info.RemoteAccessServices) != 3 {
		t.Errorf("expected 3 remote access services, got %d", len(info.RemoteAccessServices))
	}

	// Admin ports: 22 (SSH), 3389 (RDP), 5900 (VNC)
	if len(info.OpenAdministrativePorts) != 3 {
		t.Errorf("expected 3 open admin ports, got %d", len(info.OpenAdministrativePorts))
	}
}

func TestGeneratePostureSummary(t *testing.T) {
	fw := shared.FirewallSecurityInfo{FirewallState: "Enabled"}
	av := shared.AntivirusProtectionInfo{
		Products: []shared.AntivirusDetails{
			{ProductName: "Windows Defender", RealTimeProtectionState: "Enabled", ServiceStatus: "Running", UpdateStatus: "Up to Date"},
		},
	}
	edr := shared.EDRXDRDetectionInfo{
		Agents: []shared.EDRXDRAgentDetails{
			{AgentName: "CrowdStrike Falcon", Running: true, HealthStatus: "Healthy"},
		},
	}
	enc := shared.DeviceEncryptionInfo{EncryptionStatus: "Encrypted"}
	hw := shared.HardwareSecurityInfo{SecureBootStatus: "Enabled", TPMStatus: "Enabled"}
	id := shared.IdentityAccessControlInfo{UACStatus: "Enabled", PatchComplianceStatus: "Compliant"}
	net := shared.NetworkExposureAccessInfo{PubliclyBoundPorts: 0}

	summary := generatePostureSummary(fw, av, edr, enc, hw, id, net)
	if summary.OverallScore != "Excellent" {
		t.Errorf("expected Excellent posture score, got %q", summary.OverallScore)
	}
	if summary.EndpointProtectionStatus != "Protected" {
		t.Errorf("expected Protected endpoint status, got %q", summary.EndpointProtectionStatus)
	}
	if len(summary.Recommendations) != 0 {
		t.Errorf("expected 0 recommendations, got %d: %v", len(summary.Recommendations), summary.Recommendations)
	}

	// Degrade posture
	fw.FirewallState = "Disabled"
	enc.EncryptionStatus = "Unencrypted"
	summary2 := generatePostureSummary(fw, av, edr, enc, hw, id, net)
	if summary2.OverallScore != "Good" {
		t.Errorf("expected Good posture score, got %q", summary2.OverallScore)
	}
	if len(summary2.Recommendations) != 2 {
		t.Errorf("expected 2 recommendations, got %d", len(summary2.Recommendations))
	}
}

func TestSimulateLinuxAndMacOS(t *testing.T) {
	// 1. Simulate Linux
	t.Run("Simulate Linux Posture", func(t *testing.T) {
		fw := collectFirewallSecurity([]shared.FirewallProfile{
			{Name: "ufw", Enabled: true},
		})

		av := shared.AntivirusProtectionInfo{
			Products: []shared.AntivirusDetails{
				{
					ProductName:             "ClamAV",
					Vendor:                  "ClamAV",
					Version:                 "0.103.0",
					RealTimeProtectionState: "Enabled",
					ServiceStatus:           "Running",
					UpdateStatus:            "Up to Date",
					ScanInfo: &shared.SecurityScanInfo{
						LastScanTime:      "2026-06-16 12:00:00",
						ScanType:          "Scheduled/On-Demand",
						ScanResult:        "Clean",
						ScannedFilesCount: 1543,
					},
				},
			},
		}

		edr := shared.EDRXDRDetectionInfo{
			Agents: []shared.EDRXDRAgentDetails{
				{
					AgentName:              "Wazuh Agent",
					Vendor:                 "Wazuh",
					AgentVersion:           "4.3.0",
					ServiceStatus:          "Running",
					HealthStatus:           "Healthy",
					ConnectivityStatus:     "Connected",
					TamperProtectionStatus: "Enabled",
					Installed:              true,
					Running:                true,
				},
			},
		}

		enc := shared.DeviceEncryptionInfo{
			EncryptionStatus:   "Encrypted",
			ProtectionStatus:   "Enabled",
			EncryptionProvider: "LUKS",
		}

		hw := shared.HardwareSecurityInfo{
			TPMStatus:        "Enabled",
			TPMVersion:       "2.0",
			SecureBootStatus: "Enabled",
		}

		id := shared.IdentityAccessControlInfo{
			SSHRootLogin:           "Disabled",
			SSHPasswordAuth:        "Disabled",
			SudoPrivilege:          "Configured",
			PatchComplianceStatus:  "Compliant",
			PendingSecurityPatches: 0,
		}

		net := shared.NetworkExposureAccessInfo{
			TotalListeningPorts:   2,
			PubliclyBoundPorts:    0,
			ActiveNetworkServices: []string{"sshd", "nginx"},
		}

		summary := generatePostureSummary(fw, av, edr, enc, hw, id, net)

		info := shared.SecurityInfo{
			FirewallSecurity:      fw,
			AntivirusProtection:   av,
			EDRXDRDetection:       edr,
			DeviceEncryption:      enc,
			HardwareSecurity:      hw,
			IdentityAccessControl: id,
			NetworkExposureAccess: net,
			PostureSummary:        summary,
		}

		jsonData, _ := json.MarshalIndent(info, "", "  ")
		t.Logf("Simulated Linux Security Info Output:\n%s", string(jsonData))

		if summary.OverallScore != "Excellent" {
			t.Errorf("expected Excellent score for secure Linux system, got %q", summary.OverallScore)
		}
	})

	// 2. Simulate macOS
	t.Run("Simulate macOS Posture", func(t *testing.T) {
		fw := collectFirewallSecurity([]shared.FirewallProfile{
			{Name: "Application Firewall", Enabled: false},
		})

		av := shared.AntivirusProtectionInfo{
			Products: []shared.AntivirusDetails{
				{
					ProductName:             "Gatekeeper",
					Vendor:                  "Apple",
					Version:                 "Unknown",
					RealTimeProtectionState: "Enabled",
					ServiceStatus:           "Running",
					UpdateStatus:            "Up to Date",
				},
				{
					ProductName:             "Malware Removal Tool",
					Vendor:                  "Apple",
					Version:                 "Unknown",
					RealTimeProtectionState: "Enabled",
					ServiceStatus:           "Running",
					ScanInfo: &shared.SecurityScanInfo{
						LastScanTime: "2026-06-16 14:00:00",
						ScanType:     "On-Access",
						ScanResult:   "Clean",
					},
				},
			},
			XProtectVersion: "2166",
			MRTInstalled:    true,
		}

		edr := shared.EDRXDRDetectionInfo{
			Agents: []shared.EDRXDRAgentDetails{
				{
					AgentName:              "CrowdStrike Falcon",
					Vendor:                 "CrowdStrike",
					AgentVersion:           "6.50.0",
					ServiceStatus:          "Running",
					HealthStatus:           "Healthy",
					ConnectivityStatus:     "Connected",
					TamperProtectionStatus: "Enabled",
					Installed:              true,
					Running:                true,
				},
			},
		}

		enc := shared.DeviceEncryptionInfo{
			EncryptionStatus:        "Encrypted",
			ProtectionStatus:        "Enabled",
			RecoveryKeyBackupStatus: "Backed Up",
			EncryptionProvider:      "FileVault",
		}

		hw := shared.HardwareSecurityInfo{
			SecureBootStatus:     "Enabled",
			SecureEnclaveStatus:  "Enabled",
			ActivationLockStatus: "Enabled",
		}

		id := shared.IdentityAccessControlInfo{
			SecureTokenStatus:      "Enabled",
			BootstrapTokenStatus:   "Enabled",
			TouchIDStatus:          "Enabled",
			PatchComplianceStatus:  "Compliant",
			RapidSecurityResponses: "Up to Date",
		}

		net := shared.NetworkExposureAccessInfo{
			TotalListeningPorts:   1,
			PubliclyBoundPorts:    1,
			ActiveNetworkServices: []string{"ssh"},
		}

		summary := generatePostureSummary(fw, av, edr, enc, hw, id, net)

		info := shared.SecurityInfo{
			FirewallSecurity:      fw,
			AntivirusProtection:   av,
			EDRXDRDetection:       edr,
			DeviceEncryption:      enc,
			HardwareSecurity:      hw,
			IdentityAccessControl: id,
			NetworkExposureAccess: net,
			PostureSummary:        summary,
		}

		jsonData, _ := json.MarshalIndent(info, "", "  ")
		t.Logf("Simulated macOS Security Info Output:\n%s", string(jsonData))

		if summary.OverallScore != "Good" {
			t.Errorf("expected Good score for macOS system, got %q", summary.OverallScore)
		}
	})
}
