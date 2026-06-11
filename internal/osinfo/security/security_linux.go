package security

import (
	"os"
	"path/filepath"
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
		AntivirusProducts:    collectAV(),
		FirewallEnabled:      enabled,
		FirewallProfiles:     profiles,
		CoreIsolation:        collectCoreIsolation(),
		SecureBootEnabled:    collectSecureBoot(),
		ListeningPorts:       collectListeningPorts(),
		USBMassStorageEnabled: collectUSBMassStorage(),
	}
}

// collectUSBMassStorage checks whether USB mass storage is active or explicitly
// blocked on Linux.
// If the usb_storage kernel module is loaded, a device is (or was recently)
// connected and mass storage is enabled. If the module is not loaded but is
// blacklisted in /etc/modprobe.d, it has been administratively disabled.
// "unknown" is returned when the module is absent but not explicitly blocked —
// this is normal when no USB drive is connected on an otherwise unrestricted system.
func collectUSBMassStorage() string {
	if _, err := os.Stat("/sys/module/usb_storage"); err == nil {
		return "enabled"
	}
	if state := usbStorageStateFromModprobeDir("/etc/modprobe.d"); state != "" {
		return state
	}
	return "unknown"
}

// usbStorageStateFromModprobeDir scans *.conf files in dir for a blacklist or
// install-to-/bin/false directive that disables the usb_storage module.
// Returns "disabled" when found, "" otherwise (including when dir is unreadable).
func usbStorageStateFromModprobeDir(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		if state := usbStorageStateFromConfFile(filepath.Join(dir, e.Name())); state != "" {
			return state
		}
	}
	return ""
}

// usbStorageStateFromConfFile checks a single modprobe.d conf file for directives
// that disable usb_storage. Returns "disabled" when found, "" otherwise.
func usbStorageStateFromConfFile(path string) string {
	data, err := os.ReadFile(path) // #nosec G304 — path comes from os.ReadDir, not user input
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(strings.ToLower(line))
		if strings.HasPrefix(l, "blacklist") && strings.Contains(l, "usb_storage") {
			return "disabled"
		}
		if strings.HasPrefix(l, "install usb_storage") && strings.Contains(l, "/bin/false") {
			return "disabled"
		}
	}
	return ""
}

// collectAV probes systemctl for known AV daemons.
func collectAV() []shared.AntivirusProduct {
	var products []shared.AntivirusProduct
	seen := map[string]bool{}
	for _, svc := range knownAVServices {
		if seen[svc.name] {
			continue
		}
		if p, ok := probeAVService(svc.service, svc.name); ok {
			seen[svc.name] = true
			products = append(products, p)
		}
	}
	return products
}

func probeAVService(service, name string) (shared.AntivirusProduct, bool) {
	output, err := shared.RunCommand("systemctl", "is-active", service)
	if err != nil {
		return shared.AntivirusProduct{}, false
	}
	state := strings.TrimSpace(output)
	if state != "active" && state != "inactive" {
		return shared.AntivirusProduct{}, false
	}
	avEnabled := "disabled"
	if state == "active" {
		avEnabled = "enabled"
	}
	return shared.AntivirusProduct{
		Name:     name,
		Enabled:  avEnabled,
		UpToDate: "unknown",
		Source:   "service",
	}, true
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
		if mode := parseSEStatusOutput(output); mode != "" {
			return mode
		}
	}
	return "unknown"
}

// parseSEStatusOutput extracts the SELinux mode from sestatus output.
func parseSEStatusOutput(output string) string {
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
	return ""
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
	return secureBootFromEFIVars("/sys/firmware/efi/efivars")
}

// secureBootFromEFIVars reads the SecureBoot EFI variable from efivarsDir.
// The variable is 5 bytes: 4-byte attribute header + 1 value byte (1=enabled, 0=disabled).
func secureBootFromEFIVars(efivarsDir string) string {
	entries, err := os.ReadDir(efivarsDir)
	if err != nil {
		return "unknown"
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "SecureBoot-") {
			data, rerr := os.ReadFile(filepath.Join(efivarsDir, e.Name()))
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
