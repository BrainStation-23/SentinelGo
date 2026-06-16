package security

import (
	"fmt"
	"log"
	"math"
	"strings"

	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"sentinelgo/internal/osinfo/shared"
)

const maxListeningPorts = 200

// Collect returns a SecurityInfo populated by platform-specific probes.
// Individual probe failures are swallowed; fields default to zero/unknown.
func Collect() shared.SecurityInfo {
	return collectSecurity()
}

func analyzeNetworkExposure(ports []shared.ListeningPort) shared.NetworkExposureAccessInfo {
	var info shared.NetworkExposureAccessInfo
	info.TotalListeningPorts = len(ports)

	activeServicesMap := make(map[string]bool)
	remoteAccessMap := make(map[string]bool)
	adminPortsMap := make(map[uint16]bool)

	isAdminPort := func(port uint16) bool {
		switch port {
		case 21, 22, 23, 139, 445, 3389, 5985, 5986:
			return true
		}
		if port >= 5900 && port <= 5906 {
			return true
		}
		return false
	}

	for _, p := range ports {
		isLocalhost := p.Address == "127.0.0.1" || p.Address == "::1" || p.Address == "localhost"
		if !isLocalhost {
			info.PubliclyBoundPorts++
		}

		if p.ProcessName != "" {
			activeServicesMap[p.ProcessName] = true
		}

		procLower := strings.ToLower(p.ProcessName)
		isRemoteAccess := false
		if strings.Contains(procLower, "ssh") ||
			strings.Contains(procLower, "rdp") ||
			strings.Contains(procLower, "vnc") ||
			strings.Contains(procLower, "anydesk") ||
			strings.Contains(procLower, "teamviewer") ||
			strings.Contains(procLower, "remote") ||
			strings.Contains(procLower, "pcanywhere") ||
			p.Port == 22 || p.Port == 3389 || (p.Port >= 5900 && p.Port <= 5906) {
			isRemoteAccess = true
		}

		if isRemoteAccess {
			name := p.ProcessName
			if name == "" {
				name = fmt.Sprintf("Unknown service on port %d", p.Port)
			}
			remoteAccessMap[name] = true
		}

		if isAdminPort(p.Port) {
			adminPortsMap[p.Port] = true
		}
	}

	info.ActiveNetworkServices = []string{}
	for s := range activeServicesMap {
		info.ActiveNetworkServices = append(info.ActiveNetworkServices, s)
	}
	info.RemoteAccessServices = []string{}
	for s := range remoteAccessMap {
		info.RemoteAccessServices = append(info.RemoteAccessServices, s)
	}
	info.OpenAdministrativePorts = []uint16{}
	for p := range adminPortsMap {
		info.OpenAdministrativePorts = append(info.OpenAdministrativePorts, p)
	}

	return info
}

func generatePostureSummary(
	fw shared.FirewallSecurityInfo,
	av shared.AntivirusProtectionInfo,
	edr shared.EDRXDRDetectionInfo,
	enc shared.DeviceEncryptionInfo,
	hw shared.HardwareSecurityInfo,
	id shared.IdentityAccessControlInfo,
	net shared.NetworkExposureAccessInfo,
) shared.SecurityPostureSummary {
	var summary shared.SecurityPostureSummary
	var recommendations []string

	summary.FirewallStatus = fw.FirewallState
	summary.EncryptionStatus = enc.EncryptionStatus

	avHealth := "None"
	realTimeProtected := false
	avUpdated := false
	if len(av.Products) > 0 {
		avHealth = "Healthy"
		for _, p := range av.Products {
			if strings.EqualFold(p.RealTimeProtectionState, "Enabled") {
				realTimeProtected = true
			}
			if strings.EqualFold(p.UpdateStatus, "Up to Date") {
				avUpdated = true
			}
			if strings.EqualFold(p.ServiceStatus, "Stopped") || strings.EqualFold(p.RealTimeProtectionState, "Disabled") {
				avHealth = "Unhealthy"
			}
		}
	} else if av.WindowsDefenderDetails != nil {
		avHealth = "Healthy"
		if av.WindowsDefenderDetails.RealTimeProtectionEnabled {
			realTimeProtected = true
		}
		if !av.WindowsDefenderDetails.RealTimeProtectionEnabled {
			avHealth = "Unhealthy"
		}
	}
	summary.AntivirusHealth = avHealth

	edrHealth := "None"
	edrRunning := false
	if len(edr.Agents) > 0 {
		edrHealth = "Healthy"
		for _, agent := range edr.Agents {
			if agent.Running {
				edrRunning = true
			}
			if agent.Unhealthy || agent.Tampered || agent.Stopped {
				edrHealth = "Unhealthy"
			}
		}
	}
	summary.EDRXDRHealth = edrHealth

	hwControls := "Weak"
	if strings.EqualFold(hw.SecureBootStatus, "Enabled") && strings.EqualFold(hw.TPMStatus, "Enabled") {
		hwControls = "Strong"
	} else if strings.EqualFold(hw.SecureBootStatus, "Unsupported") || strings.EqualFold(hw.TPMStatus, "Unsupported") {
		hwControls = "Unsupported"
	}
	summary.HardwareSecurityControls = hwControls

	idControls := "Configured"
	isAtRisk := false
	if id.UACStatus == "Disabled" {
		isAtRisk = true
		recommendations = append(recommendations, "Enable User Account Control (UAC) to prevent unauthorized changes.")
	}
	if strings.EqualFold(id.SSHRootLogin, "Enabled") {
		isAtRisk = true
		recommendations = append(recommendations, "Disable SSH root login to prevent brute force root attacks.")
	}
	if strings.EqualFold(id.SSHPasswordAuth, "Enabled") {
		recommendations = append(recommendations, "Disable SSH password authentication and use SSH keys instead.")
	}
	if isAtRisk {
		idControls = "At Risk"
	}
	summary.IdentitySecurityControls = idControls

	exposure := "Low"
	if net.PubliclyBoundPorts > 5 || len(net.OpenAdministrativePorts) > 1 {
		exposure = "High"
		recommendations = append(recommendations, "Close or restrict publicly bound administrative ports (e.g., SSH, RDP).")
	} else if net.PubliclyBoundPorts > 0 {
		exposure = "Medium"
		recommendations = append(recommendations, "Ensure listening services bound to public interfaces are protected.")
	}
	summary.NetworkExposureLevel = exposure

	if !strings.EqualFold(fw.FirewallState, "Enabled") {
		recommendations = append(recommendations, "Enable host firewall protection.")
	}
	if len(av.Products) == 0 && av.WindowsDefenderDetails == nil {
		recommendations = append(recommendations, "Install an Antivirus product to protect the endpoint.")
	} else {
		if !realTimeProtected {
			recommendations = append(recommendations, "Enable Real-Time Protection for Antivirus.")
		}
		if !avUpdated && avHealth != "None" {
			recommendations = append(recommendations, "Update Antivirus signature definitions.")
		}
	}
	if len(edr.Agents) == 0 {
		recommendations = append(recommendations, "Install an EDR/XDR sensor for advanced threat detection.")
	} else if !edrRunning {
		recommendations = append(recommendations, "Start the stopped EDR/XDR agent service.")
	}
	if !strings.EqualFold(enc.EncryptionStatus, "Encrypted") {
		recommendations = append(recommendations, "Configure device encryption (BitLocker/FileVault/LUKS) to protect local data.")
	}
	if strings.EqualFold(hw.SecureBootStatus, "Disabled") {
		recommendations = append(recommendations, "Enable UEFI Secure Boot in system firmware.")
	}

	summary.Recommendations = recommendations

	scoreCount := 0
	if strings.EqualFold(fw.FirewallState, "Enabled") {
		scoreCount++
	}
	if avHealth == "Healthy" {
		scoreCount++
	}
	if edrHealth == "Healthy" {
		scoreCount++
	}
	if strings.EqualFold(enc.EncryptionStatus, "Encrypted") {
		scoreCount++
	}
	if hwControls == "Strong" {
		scoreCount++
	}
	if idControls == "Configured" {
		scoreCount++
	}
	if exposure == "Low" {
		scoreCount++
	}

	summary.OverallScore = "Poor"
	if scoreCount >= 6 {
		summary.OverallScore = "Excellent"
	} else if scoreCount >= 4 {
		summary.OverallScore = "Good"
	} else if scoreCount >= 2 {
		summary.OverallScore = "Fair"
	}

	summary.EndpointProtectionStatus = "At Risk"
	if avHealth == "Healthy" || edrHealth == "Healthy" {
		summary.EndpointProtectionStatus = "Protected"
	}

	return summary
}

// collectListeningPorts enumerates listening TCP ports and bound UDP ports
// using gopsutil, which works cross-platform without exec calls.
func collectListeningPorts() []shared.ListeningPort {
	conns, err := gnet.Connections("all")
	if err != nil {
		log.Printf("security: listening ports: %v", err)
		return nil
	}

	var ports []shared.ListeningPort
	for _, conn := range conns {
		// TCP: must be in LISTEN state. UDP (SOCK_DGRAM=2): any socket with a bound port.
		isTCPListen := conn.Status == "LISTEN"
		isUDPBound := conn.Type == 2 && conn.Laddr.Port > 0
		if !isTCPListen && !isUDPBound {
			continue
		}
		if conn.Laddr.Port > math.MaxUint16 {
			continue
		}

		proto := "tcp"
		if conn.Type == 2 {
			proto = "udp"
		}

		lp := shared.ListeningPort{
			Protocol:  proto,
			Port:      uint16(conn.Laddr.Port),
			Address:   conn.Laddr.IP,
			ProcessID: conn.Pid,
		}
		if conn.Pid > 0 {
			if p, perr := process.NewProcess(conn.Pid); perr == nil {
				if name, nerr := p.Name(); nerr == nil {
					lp.ProcessName = name
				}
			}
		}

		ports = append(ports, lp)
		if len(ports) >= maxListeningPorts {
			log.Printf("security: listening ports truncated at %d", maxListeningPorts)
			break
		}
	}
	return ports
}
