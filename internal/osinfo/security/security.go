package security

import (
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
	if r.exposure != "High" {
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

// processNameForPID best-effort resolves pid's executable name via gopsutil.
// Returns "" if the process can't be inspected (e.g. it exited, or the
// lookup requires privileges this process doesn't have).
func processNameForPID(pid int32) string {
	p, err := process.NewProcess(pid)
	if err != nil {
		return ""
	}
	name, err := p.Name()
	if err != nil {
		return ""
	}
	return name
}

// classifyListeningPort converts a gopsutil connection into a ListeningPort,
// with ok=false for connections that are neither a TCP listener nor a bound
// UDP socket (SOCK_DGRAM=2), or whose port doesn't fit in a uint16.
func classifyListeningPort(conn gnet.ConnectionStat) (lp shared.ListeningPort, ok bool) {
	isTCPListen := conn.Status == "LISTEN"
	isUDPBound := conn.Type == 2 && conn.Laddr.Port > 0
	if !isTCPListen && !isUDPBound {
		return lp, false
	}
	if conn.Laddr.Port > math.MaxUint16 {
		return lp, false
	}

	proto := "tcp"
	if conn.Type == 2 {
		proto = "udp"
	}

	lp = shared.ListeningPort{
		Protocol:  proto,
		Port:      uint16(conn.Laddr.Port),
		Address:   conn.Laddr.IP,
		ProcessID: conn.Pid,
	}
	if conn.Pid > 0 {
		lp.ProcessName = processNameForPID(conn.Pid)
	}
	return lp, true
}

// collectListeningPorts enumerates every listening TCP port and bound UDP
// port using gopsutil, which works cross-platform without exec calls. The
// whole list feeds the exposure analysis, so a risky service can't be missed
// on a busy host; only the copy uploaded as listening_ports is capped
// (uploadedListeningPorts).
func collectListeningPorts() []shared.ListeningPort {
	conns, err := gnet.Connections("all")
	if err != nil {
		log.Printf("security: listening ports: %v", err)
		return nil
	}

	var ports []shared.ListeningPort
	for _, conn := range conns {
		if lp, ok := classifyListeningPort(conn); ok {
			ports = append(ports, lp)
		}
	}
	return ports
}

// uploadedListeningPorts caps the listening_ports payload at
// maxListeningPorts entries.
func uploadedListeningPorts(ports []shared.ListeningPort) []shared.ListeningPort {
	if len(ports) <= maxListeningPorts {
		return ports
	}
	log.Printf("security: listening ports truncated at %d of %d", maxListeningPorts, len(ports))
	return ports[:maxListeningPorts]
}
