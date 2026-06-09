package security

import (
	"os"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// knownAVServices lists systemd service names for common endpoint-protection products.
var knownAVServices = []struct {
	service string
	name    string
}{
	{"clamav-daemon", "ClamAV"},
	{"clamd", "ClamAV"},
	{"falcon-sensor", "CrowdStrike Falcon"},
	{"falcond", "CrowdStrike Falcon"},
	{"cbsensor", "Carbon Black"},
	{"ds_agent", "Trend Micro Deep Security"},
	{"sophos-spl", "Sophos"},
	{"sav-protect", "Sophos AV"},
	{"symantec_antivirus", "Symantec Antivirus"},
	{"eset-daemon", "ESET"},
}

func collectSecurity() shared.SecurityInfo {
	profiles := collectFirewallProfiles()
	enabled := false
	for _, p := range profiles {
		if p.Enabled {
			enabled = true
			break
		}
	}
	return shared.SecurityInfo{
		AntivirusProducts: collectAV(),
		FirewallEnabled:   enabled,
		FirewallProfiles:  profiles,
		CoreIsolation:     collectCoreIsolation(),
		SecureBootEnabled: collectSecureBoot(),
		ListeningPorts:    collectListeningPorts(),
	}
}

// collectAV probes systemctl for known AV daemons.
func collectAV() []shared.AntivirusProduct {
	var products []shared.AntivirusProduct
	seen := map[string]bool{}
	for _, svc := range knownAVServices {
		if seen[svc.name] {
			continue
		}
		output, err := shared.RunCommand("systemctl", "is-active", svc.service)
		if err != nil {
			continue
		}
		state := strings.TrimSpace(output)
		if state != "active" && state != "inactive" {
			continue
		}
		seen[svc.name] = true
		avEnabled := "disabled"
		if state == "active" {
			avEnabled = "enabled"
		}
		products = append(products, shared.AntivirusProduct{
			Name:     svc.name,
			Enabled:  avEnabled,
			UpToDate: "unknown",
			Source:   "service",
		})
	}
	return products
}

// collectFirewallProfiles tries ufw, then firewalld, then iptables.
func collectFirewallProfiles() []shared.FirewallProfile {
	if output, err := shared.RunCommand("ufw", "status"); err == nil {
		// First line is "Status: active" or "Status: inactive".
		first := strings.ToLower(strings.SplitN(output, "\n", 2)[0])
		active := strings.Contains(first, "active") && !strings.Contains(first, "inactive")
		return []shared.FirewallProfile{{Name: "ufw", Enabled: active}}
	}
	if output, err := shared.RunCommand("firewall-cmd", "--state"); err == nil {
		running := strings.TrimSpace(strings.ToLower(output)) == "running"
		return []shared.FirewallProfile{{Name: "firewalld", Enabled: running}}
	}
	if _, err := shared.RunCommand("iptables", "-L", "-n"); err == nil {
		return []shared.FirewallProfile{{Name: "iptables", Enabled: true}}
	}
	return nil
}

func collectCoreIsolation() shared.CoreIsolationInfo {
	return shared.CoreIsolationInfo{
		SELinuxMode:     collectSELinux(),
		AppArmorEnabled: collectAppArmor(),
		KernelLockdown:  collectKernelLockdown(),
	}
}

// collectSELinux reads the SELinux enforcement mode from sysfs or sestatus.
func collectSELinux() string {
	if data, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		switch strings.TrimSpace(string(data)) {
		case "1":
			return "enforcing"
		case "0":
			return "permissive"
		}
	}
	if output, err := shared.RunCommand("sestatus"); err == nil {
		for _, line := range strings.Split(output, "\n") {
			lower := strings.ToLower(strings.TrimSpace(line))
			if strings.HasPrefix(lower, "selinux status:") && strings.Contains(lower, "disabled") {
				return "disabled"
			}
			if strings.HasPrefix(lower, "current mode:") {
				parts := strings.Fields(line)
				if len(parts) > 0 {
					mode := strings.ToLower(parts[len(parts)-1])
					if mode == "enforcing" || mode == "permissive" {
						return mode
					}
				}
			}
		}
	}
	return "unknown"
}

// collectAppArmor returns true when AppArmor is loaded.
func collectAppArmor() bool {
	if _, err := os.Stat("/sys/kernel/security/apparmor"); err == nil {
		return true
	}
	_, err := shared.RunCommand("aa-status", "--enabled")
	return err == nil
}

// collectKernelLockdown reads the active kernel lockdown mode from sysfs.
// The active mode is enclosed in brackets: "none [integrity] confidentiality"
func collectKernelLockdown() string {
	data, err := os.ReadFile("/sys/kernel/security/lockdown")
	if err != nil {
		return "unknown"
	}
	content := string(data)
	for _, mode := range []string{"confidentiality", "integrity", "none"} {
		if strings.Contains(content, "["+mode+"]") {
			return mode
		}
	}
	return "unknown"
}

// collectSecureBoot checks UEFI Secure Boot state via mokutil or EFI variables.
func collectSecureBoot() string {
	if output, err := shared.RunCommand("mokutil", "--sb-state"); err == nil {
		lower := strings.ToLower(strings.TrimSpace(output))
		if strings.Contains(lower, "secureboot enabled") {
			return "enabled"
		}
		if strings.Contains(lower, "secureboot disabled") {
			return "disabled"
		}
	}
	// Fallback: read SecureBoot EFI variable (4-byte attribute header + 1 value byte).
	entries, err := os.ReadDir("/sys/firmware/efi/efivars")
	if err != nil {
		return "unknown"
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "SecureBoot-") {
			data, rerr := os.ReadFile("/sys/firmware/efi/efivars/" + e.Name())
			if rerr == nil && len(data) >= 5 {
				if data[4] == 1 {
					return "enabled"
				}
				return "disabled"
			}
			break
		}
	}
	return "unknown"
}
