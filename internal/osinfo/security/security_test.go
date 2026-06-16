package security

import (
	"encoding/json"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

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

	// Services are sorted deterministically
	if info.ActiveNetworkServices[0] != "node" {
		t.Errorf("expected sorted active network services, first should be 'node', got %q", info.ActiveNetworkServices[0])
	}

	// Remote access detection: sshd (22), termservice (3389), vncserver (5900)
	if len(info.RemoteAccessServices) != 3 {
		t.Errorf("expected 3 remote access services, got %d", len(info.RemoteAccessServices))
	}

	// Admin ports: 22 (SSH), 3389 (RDP), 5900 (VNC)
	if len(info.OpenAdministrativePorts) != 3 {
		t.Errorf("expected 3 open admin ports, got %d", len(info.OpenAdministrativePorts))
	}
	if info.OpenAdministrativePorts[0] != 22 || info.OpenAdministrativePorts[1] != 3389 || info.OpenAdministrativePorts[2] != 5900 {
		t.Errorf("expected sorted administrative ports [22, 3389, 5900], got %v", info.OpenAdministrativePorts)
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

func TestGeneratePostureSummary_AVUpdatedRecommendation(t *testing.T) {
	fw := shared.FirewallSecurityInfo{FirewallState: "Enabled"}
	edr := shared.EDRXDRDetectionInfo{
		Agents: []shared.EDRXDRAgentDetails{
			{AgentName: "CrowdStrike Falcon", Running: true, HealthStatus: "Healthy"},
		},
	}
	enc := shared.DeviceEncryptionInfo{EncryptionStatus: "Encrypted"}
	hw := shared.HardwareSecurityInfo{SecureBootStatus: "Enabled", TPMStatus: "Enabled"}
	id := shared.IdentityAccessControlInfo{UACStatus: "Enabled", PatchComplianceStatus: "Compliant"}
	net := shared.NetworkExposureAccessInfo{PubliclyBoundPorts: 0}

	// Case A: 2 products, one is out of date. Should trigger recommendation.
	avOutdated := shared.AntivirusProtectionInfo{
		Products: []shared.AntivirusDetails{
			{ProductName: "AV1", RealTimeProtectionState: "Enabled", ServiceStatus: "Running", UpdateStatus: "Up to Date"},
			{ProductName: "AV2", RealTimeProtectionState: "Enabled", ServiceStatus: "Running", UpdateStatus: "Out of Date"},
		},
	}
	summaryA := generatePostureSummary(fw, avOutdated, edr, enc, hw, id, net)
	hasUpdateRec := false
	for _, rec := range summaryA.Recommendations {
		if rec == "Update Antivirus signature definitions." {
			hasUpdateRec = true
		}
	}
	if !hasUpdateRec {
		t.Error("expected recommendation to update AV signatures when one AV product is out of date")
	}

	// Case B: Windows Defender is healthy but update status was missing. Since it defaults to avUpdated=true, it shouldn't trigger update recommendation.
	avDefenderOnly := shared.AntivirusProtectionInfo{
		WindowsDefenderDetails: &shared.WindowsDefenderDetails{
			RealTimeProtectionEnabled: true,
		},
	}
	summaryB := generatePostureSummary(fw, avDefenderOnly, edr, enc, hw, id, net)
	hasDefenderUpdateRec := false
	for _, rec := range summaryB.Recommendations {
		if rec == "Update Antivirus signature definitions." {
			hasDefenderUpdateRec = true
		}
	}
	if hasDefenderUpdateRec {
		t.Error("should not suggest updating AV signatures for Windows Defender when its update status is unknown/not marked dirty")
	}
}

func TestCollectFirewallSecurity_LinuxMacOSShapes(t *testing.T) {
	// 1. All enabled -> FirewallState = "Enabled"
	profilesAllOn := []shared.FirewallProfile{
		{Name: "ufw", Enabled: true},
	}
	resAllOn := collectFirewallSecurity(profilesAllOn)
	if resAllOn.FirewallState != "Enabled" {
		t.Errorf("expected Enabled firewall state, got %q", resAllOn.FirewallState)
	}

	// 2. None enabled -> FirewallState = "Disabled"
	profilesAllOff := []shared.FirewallProfile{
		{Name: "Application Firewall", Enabled: false},
	}
	resAllOff := collectFirewallSecurity(profilesAllOff)
	if resAllOff.FirewallState != "Disabled" {
		t.Errorf("expected Disabled firewall state, got %q", resAllOff.FirewallState)
	}

	// 3. Mixed -> FirewallState = "Partially Enabled"
	profilesMixed := []shared.FirewallProfile{
		{Name: "Private", Enabled: true},
		{Name: "Public", Enabled: false},
	}
	resMixed := collectFirewallSecurity(profilesMixed)
	if resMixed.FirewallState != "Partially Enabled" {
		t.Errorf("expected Partially Enabled firewall state, got %q", resMixed.FirewallState)
	}

	// 4. Partially Enabled contributes to recommendations but not to score
	fw := resMixed // Partially Enabled
	av := shared.AntivirusProtectionInfo{
		Products: []shared.AntivirusDetails{
			{ProductName: "AV", RealTimeProtectionState: "Enabled", ServiceStatus: "Running", UpdateStatus: "Up to Date"},
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
	// FirewallState is not "Enabled", so it does not count for scoreCount.
	// Excellent needs 7+. Max without firewall is 7. If it counts partially enabled, it would be 8.
	if summary.OverallScore != "Excellent" { // 7 points out of 8 (no firewall point, but others are green)
		t.Errorf("expected score to be Excellent (7 points), got %q", summary.OverallScore)
	}

	// If we disable everything else, check recommendation
	hasFirewallRec := false
	for _, rec := range summary.Recommendations {
		if rec == "Enable host firewall protection." {
			hasFirewallRec = true
		}
	}
	if !hasFirewallRec {
		t.Error("expected recommendation to enable firewall protection when status is Partially Enabled")
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
					ConnectivityStatus:     "Unknown",
					TamperProtectionStatus: "Unknown",
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
					ConnectivityStatus:     "Unknown",
					TamperProtectionStatus: "Unknown",
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
