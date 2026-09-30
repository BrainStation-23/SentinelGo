package security

import (
	"fmt"
	"log"
	"math"
	"sort"
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

func collectFirewallSecurity(profiles []shared.FirewallProfile) shared.FirewallSecurityInfo {
	var f shared.FirewallSecurityInfo
	f.Profiles = profiles
	allEnabled := true
	anyEnabled := false
	for _, p := range profiles {
		f.ActiveProfiles = append(f.ActiveProfiles, p.Name)
		if p.Enabled {
			anyEnabled = true
		} else {
			allEnabled = false
		}
	}
	f.FirewallState = "Disabled"
	if allEnabled && len(profiles) > 0 {
		f.FirewallState = "Enabled"
	} else if anyEnabled {
		f.FirewallState = "Partially Enabled"
	}
	return f
}

// isLocalAddress reports whether addr is a loopback address, used to decide
// whether a listening port counts as publicly bound.
func isLocalAddress(addr string) bool {
	return addr == "127.0.0.1" || addr == "::1" || addr == "localhost"
}

// remoteAccessProcessKeywords are process-name substrings that indicate a
// remote-access tool (case-insensitive match against the process name).
var remoteAccessProcessKeywords = []string{
	"ssh", "rdp", "vnc", "anydesk", "teamviewer", "remote", "pcanywhere",
}

// isRemoteAccessPort reports whether p looks like a remote-access service,
// either by its process name or by listening on a well-known remote-access port.
func isRemoteAccessPort(p shared.ListeningPort) bool {
	procLower := strings.ToLower(p.ProcessName)
	for _, kw := range remoteAccessProcessKeywords {
		if strings.Contains(procLower, kw) {
			return true
		}
	}
	return p.Port == 22 || p.Port == 3389 || (p.Port >= 5900 && p.Port <= 5906)
}

// isAdminPort reports whether port is a well-known administrative service port.
func isAdminPort(port uint16) bool {
	switch port {
	case 21, 22, 23, 139, 445, 3389, 5985, 5986:
		return true
	}
	return port >= 5900 && port <= 5906
}

func analyzeNetworkExposure(ports []shared.ListeningPort) shared.NetworkExposureAccessInfo {
	var info shared.NetworkExposureAccessInfo
	info.TotalListeningPorts = len(ports)

	activeServicesMap := make(map[string]bool)
	remoteAccessMap := make(map[string]bool)
	adminPortsMap := make(map[uint16]bool)

	for _, p := range ports {
		if !isLocalAddress(p.Address) {
			info.PubliclyBoundPorts++
		}

		if p.ProcessName != "" {
			activeServicesMap[p.ProcessName] = true
		}

		if isRemoteAccessPort(p) {
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
	sort.Strings(info.ActiveNetworkServices)

	info.RemoteAccessServices = []string{}
	for s := range remoteAccessMap {
		info.RemoteAccessServices = append(info.RemoteAccessServices, s)
	}
	sort.Strings(info.RemoteAccessServices)

	info.OpenAdministrativePorts = []uint16{}
	for p := range adminPortsMap {
		info.OpenAdministrativePorts = append(info.OpenAdministrativePorts, p)
	}
	sort.Slice(info.OpenAdministrativePorts, func(i, j int) bool {
		return info.OpenAdministrativePorts[i] < info.OpenAdministrativePorts[j]
	})

	return info
}

// avStatus bundles the antivirus health verdict computed by summarizeAntivirus.
// Grouping these together keeps downstream function signatures short.
type avStatus struct {
	health            string
	realTimeProtected bool
	updated           bool
}

// summarizeAntivirus derives an overall AV health verdict from either the
// generic Products list or, when that's empty, the Windows Defender-specific
// details. updated defaults to false when no AV is present at all.
func summarizeAntivirus(av shared.AntivirusProtectionInfo) avStatus {
	if len(av.Products) > 0 {
		return summarizeAVProducts(av.Products)
	}
	if av.WindowsDefenderDetails != nil {
		return summarizeWindowsDefender(av.WindowsDefenderDetails)
	}
	return avStatus{health: "None"}
}

func summarizeAVProducts(products []shared.AntivirusDetails) avStatus {
	s := avStatus{health: "Healthy", updated: true}
	for _, p := range products {
		if strings.EqualFold(p.RealTimeProtectionState, "Enabled") {
			s.realTimeProtected = true
		}
		if strings.EqualFold(p.UpdateStatus, "Out of Date") {
			s.updated = false
		}
		if strings.EqualFold(p.ServiceStatus, "Stopped") || strings.EqualFold(p.RealTimeProtectionState, "Disabled") {
			s.health = "Unhealthy"
		}
	}
	return s
}

func summarizeWindowsDefender(d *shared.WindowsDefenderDetails) avStatus {
	s := avStatus{health: "Healthy", updated: true, realTimeProtected: d.RealTimeProtectionEnabled}
	if !d.RealTimeProtectionEnabled {
		s.health = "Unhealthy"
	}
	return s
}

// summarizeEDR derives an overall EDR/XDR health verdict from the agent list.
func summarizeEDR(edr shared.EDRXDRDetectionInfo) (health string, running bool) {
	health = "None"
	if len(edr.Agents) > 0 {
		health = "Healthy"
		for _, agent := range edr.Agents {
			if agent.Running {
				running = true
			}
			if agent.Unhealthy || agent.Tampered || agent.Stopped {
				health = "Unhealthy"
			}
		}
	}
	return health, running
}

// summarizeHardwareControls rates Secure Boot + TPM as Strong (both enabled),
// Unsupported (either is unsupported by the hardware), or Weak (otherwise).
func summarizeHardwareControls(hw shared.HardwareSecurityInfo) string {
	switch {
	case strings.EqualFold(hw.SecureBootStatus, "Enabled") && strings.EqualFold(hw.TPMStatus, "Enabled"):
		return "Strong"
	case strings.EqualFold(hw.SecureBootStatus, "Unsupported") || strings.EqualFold(hw.TPMStatus, "Unsupported"):
		return "Unsupported"
	default:
		return "Weak"
	}
}

// summarizeIdentityControls rates identity/access posture and collects the
// recommendations specific to that assessment (UAC, SSH hardening, patching).
func summarizeIdentityControls(id shared.IdentityAccessControlInfo) (controls string, recommendations []string) {
	controls = "Configured"
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
	if strings.EqualFold(id.PatchComplianceStatus, "Non-Compliant") {
		recommendations = append(recommendations, "Install pending security updates to maintain system compliance.")
	}
	if isAtRisk {
		controls = "At Risk"
	}
	return controls, recommendations
}

// summarizeNetworkExposureLevel rates public exposure and, when elevated,
// returns the matching recommendation.
func summarizeNetworkExposureLevel(net shared.NetworkExposureAccessInfo) (level string, recommendations []string) {
	switch {
	case net.PubliclyBoundPorts > 5 || len(net.OpenAdministrativePorts) > 1:
		return "High", []string{"Close or restrict publicly bound administrative ports (e.g., SSH, RDP)."}
	case net.PubliclyBoundPorts > 0:
		return "Medium", []string{"Ensure listening services bound to public interfaces are protected."}
	default:
		return "Low", nil
	}
}

// postureRatings bundles the per-category verdicts generatePostureSummary
// computes before scoring, keeping computePostureScore's signature short.
type postureRatings struct {
	avHealth   string
	edrHealth  string
	hwControls string
	idControls string
	exposure   string
}

// buildProtectionRecommendations covers the endpoint-protection checks that
// don't belong to a single sub-score: firewall, AV presence/health, EDR
// presence/health, encryption, and Secure Boot.
func buildProtectionRecommendations(
	fw shared.FirewallSecurityInfo,
	av shared.AntivirusProtectionInfo,
	edr shared.EDRXDRDetectionInfo,
	enc shared.DeviceEncryptionInfo,
	hw shared.HardwareSecurityInfo,
	avs avStatus,
	edrRunning bool,
) []string {
	var recommendations []string

	if !strings.EqualFold(fw.FirewallState, "Enabled") {
		recommendations = append(recommendations, "Enable host firewall protection.")
	}
	if len(av.Products) == 0 && av.WindowsDefenderDetails == nil {
		recommendations = append(recommendations, "Install an Antivirus product to protect the endpoint.")
	} else {
		if !avs.realTimeProtected {
			recommendations = append(recommendations, "Enable Real-Time Protection for Antivirus.")
		}
		if !avs.updated && avs.health != "None" {
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

	return recommendations
}

// computePostureScore counts how many of the 8 independent posture checks
// are in their "good" state; generatePostureSummary maps the count to a
// letter-grade-style OverallScore.
func computePostureScore(
	fw shared.FirewallSecurityInfo,
	enc shared.DeviceEncryptionInfo,
	id shared.IdentityAccessControlInfo,
	r postureRatings,
) int {
	score := 0
	if strings.EqualFold(fw.FirewallState, "Enabled") {
		score++
	}
	if r.avHealth == "Healthy" {
		score++
	}
	if r.edrHealth == "Healthy" {
		score++
	}
	if strings.EqualFold(enc.EncryptionStatus, "Encrypted") {
		score++
	}
	if r.hwControls == "Strong" {
		score++
	}
	if r.idControls == "Configured" {
		score++
	}
	if r.exposure == "Low" {
		score++
	}
	if strings.EqualFold(id.PatchComplianceStatus, "Compliant") {
		score++
	}
	return score
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
	summary.FirewallStatus = fw.FirewallState
	summary.EncryptionStatus = enc.EncryptionStatus

	avs := summarizeAntivirus(av)
	summary.AntivirusHealth = avs.health

	edrHealth, edrRunning := summarizeEDR(edr)
	summary.EDRXDRHealth = edrHealth

	hwControls := summarizeHardwareControls(hw)
	summary.HardwareSecurityControls = hwControls

	idControls, idRecommendations := summarizeIdentityControls(id)
	summary.IdentitySecurityControls = idControls

	exposure, exposureRecommendations := summarizeNetworkExposureLevel(net)
	summary.NetworkExposureLevel = exposure

	protectionRecommendations := buildProtectionRecommendations(fw, av, edr, enc, hw, avs, edrRunning)

	var recommendations []string
	recommendations = append(recommendations, idRecommendations...)
	recommendations = append(recommendations, exposureRecommendations...)
	recommendations = append(recommendations, protectionRecommendations...)
	summary.Recommendations = recommendations

	ratings := postureRatings{avHealth: avs.health, edrHealth: edrHealth, hwControls: hwControls, idControls: idControls, exposure: exposure}
	scoreCount := computePostureScore(fw, enc, id, ratings)
	summary.OverallScore = "Poor"
	if scoreCount >= 7 {
		summary.OverallScore = "Excellent"
	} else if scoreCount >= 5 {
		summary.OverallScore = "Good"
	} else if scoreCount >= 3 {
		summary.OverallScore = "Fair"
	}

	summary.EndpointProtectionStatus = "At Risk"
	if avs.health == "Healthy" || edrHealth == "Healthy" {
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
