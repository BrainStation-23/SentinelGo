//go:build linux

package security

// Hermetic tests for the Linux security collectors. securityRunCommand and
// securityRunCommandOutput return fixture output for exactly the commands a
// test expects (anything else fails as "not installed"), and
// securityHostRoot points every absolute path at a fake root filesystem in
// t.TempDir(). Nothing here reads the host's /proc, /sys or /etc.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

type linuxCmdResult struct {
	out    string // what the command writes to stdout
	stderr string // what the command writes to stderr
	code   int
}

// stubLinuxSecurityCommands replaces both command runners. outputs is keyed by
// the space-joined command line; RunCommand succeeds only for code 0 and sees
// only stdout, while RunCommandOutput returns the code as-is and sees stdout
// followed by stderr (mirroring the real helpers' Output vs CombinedOutput).
func stubLinuxSecurityCommands(t *testing.T, outputs map[string]linuxCmdResult) {
	t.Helper()
	origRun, origOut := securityRunCommand, securityRunCommandOutput
	t.Cleanup(func() {
		securityRunCommand = origRun
		securityRunCommandOutput = origOut
	})
	lookup := func(name string, args []string) (linuxCmdResult, bool) {
		r, ok := outputs[strings.Join(append([]string{name}, args...), " ")]
		return r, ok
	}
	securityRunCommand = func(name string, args ...string) (string, error) {
		r, ok := lookup(name, args)
		if !ok {
			return "", errors.New("command not available")
		}
		if r.code != 0 {
			return "", errors.New("exit status")
		}
		return r.out, nil
	}
	securityRunCommandOutput = func(name string, args ...string) (string, int, error) {
		r, ok := lookup(name, args)
		if !ok {
			return "", -1, errors.New("command not available")
		}
		return r.out + r.stderr, r.code, nil
	}
}

// cmdOK is shorthand for a successful command with the given stdout.
func cmdOK(out string) linuxCmdResult { return linuxCmdResult{out: out} }

// stubLinuxSecurityRoot points securityHostRoot at an empty fake root.
func stubLinuxSecurityRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	orig := securityHostRoot
	t.Cleanup(func() { securityHostRoot = orig })
	securityHostRoot = root
	return root
}

// writeRootFile writes content at the absolute path p inside the fake root.
func writeRootFile(t *testing.T, root, p, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(p))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mkRootDir(t *testing.T, root, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(p)), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestCollectSecurity_EndToEnd(t *testing.T) {
	root := stubLinuxSecurityRoot(t)
	writeRootFile(t, root, "/etc/ssh/sshd_config",
		"# managed\nPermitRootLogin prohibit-password\nPasswordAuthentication no\nPubkeyAuthentication yes\n")
	writeRootFile(t, root, "/etc/group", "root:x:0:\nsudo:x:27:alice\n")
	writeRootFile(t, root, "/sys/fs/selinux/enforce", "1\n")
	mkRootDir(t, root, "/sys/kernel/security/apparmor")
	writeRootFile(t, root, "/sys/kernel/security/lockdown", "none [integrity] confidentiality\n")
	mkRootDir(t, root, "/sys/module/usb_storage")
	writeRootFile(t, root, "/dev/tpm0", "")
	writeRootFile(t, root, "/sys/class/tpm/tpm0/tpm_version_major", "2\n")
	writeRootFile(t, root, "/proc/1/comm", "systemd\n")
	writeRootFile(t, root, "/usr/bin/apt-get", "")

	stubLinuxSecurityCommands(t, map[string]linuxCmdResult{
		"ufw status":                        cmdOK("Status: active\n\nTo Action From\n"),
		"systemctl is-active clamav-daemon": cmdOK("active\n"),
		"systemctl is-active osqueryd":      cmdOK("active\n"),
		"systemctl is-enabled osqueryd":     cmdOK("enabled\n"),
		"mokutil --sb-state":                cmdOK("SecureBoot enabled\n"),
		"lsblk -o NAME,FSTYPE":              cmdOK("NAME FSTYPE\nsda\n└─sda3 crypto_LUKS\n"),
		"apt-get -s upgrade":                cmdOK("Inst openssl [3.0.2-0ubuntu1.15] (3.0.2-0ubuntu1.16 Ubuntu:22.04/jammy-security [amd64])\n"),
	})

	info := collectSecurity()

	if !info.FirewallEnabled || len(info.FirewallProfiles) != 1 || info.FirewallProfiles[0].Name != "ufw" {
		t.Errorf("firewall = %v %+v", info.FirewallEnabled, info.FirewallProfiles)
	}
	if len(info.AntivirusProducts) != 1 || info.AntivirusProducts[0].Name != "ClamAV" ||
		info.AntivirusProducts[0].Enabled != "enabled" {
		t.Errorf("AV products = %+v", info.AntivirusProducts)
	}
	if len(info.AntivirusProtection.Products) != 1 || info.AntivirusProtection.Products[0].ScanInfo == nil {
		t.Errorf("AV protection = %+v", info.AntivirusProtection)
	}
	if info.CoreIsolation.SELinuxMode != "enforcing" || !info.CoreIsolation.AppArmorEnabled ||
		info.CoreIsolation.KernelLockdown != "integrity" {
		t.Errorf("core isolation = %+v", info.CoreIsolation)
	}
	if info.KernelHardening.SELinuxMode != "enforcing" || info.KernelHardening.USBMassStorageEnabled != "enabled" {
		t.Errorf("kernel hardening = %+v", info.KernelHardening)
	}
	if info.SecureBootEnabled != "enabled" || info.USBMassStorageEnabled != "enabled" {
		t.Errorf("secure boot = %q, usb = %q", info.SecureBootEnabled, info.USBMassStorageEnabled)
	}
	if info.DeviceEncryption.EncryptionProvider != "LUKS" {
		t.Errorf("encryption = %+v", info.DeviceEncryption)
	}
	if info.HardwareSecurity.TPMStatus != "Enabled" || info.HardwareSecurity.TPMVersion != "2.0" ||
		info.HardwareSecurity.SecureBootStatus != "enabled" {
		t.Errorf("hardware = %+v", info.HardwareSecurity)
	}
	id := info.IdentityAccessControl
	if id.SSHRootLogin != "Disabled" || id.SSHPasswordAuth != "Disabled" || id.SudoPrivilege != "Configured" ||
		id.PendingSecurityPatches != 1 || id.PatchComplianceStatus != "Non-Compliant" {
		t.Errorf("identity = %+v", id)
	}
	if info.NetworkExposureAccess.SSHKeyAuthStatus != "Enabled" ||
		info.NetworkExposureAccess.SSHRootLoginStatus != "Disabled" {
		t.Errorf("network exposure = %+v", info.NetworkExposureAccess)
	}
	if len(info.EDRXDRDetection.Agents) != 1 || info.EDRXDRDetection.Agents[0].AgentName != "Osquery" {
		t.Errorf("EDR = %+v", info.EDRXDRDetection)
	}
}

func TestCollectFirewallProfiles(t *testing.T) {
	cases := []struct {
		name    string
		cmds    map[string]linuxCmdResult
		want    string
		enabled bool
	}{
		{"ufw active", map[string]linuxCmdResult{"ufw status": cmdOK("Status: active\n")}, "ufw", true},
		{"ufw inactive", map[string]linuxCmdResult{"ufw status": cmdOK("Status: inactive\n")}, "ufw", false},
		{"firewalld running", map[string]linuxCmdResult{"firewall-cmd --state": cmdOK("running\n")}, "firewalld", true},
		{"firewalld not running", map[string]linuxCmdResult{"firewall-cmd --state": cmdOK("not running\n")}, "firewalld", false},
		{"iptables with DROP", map[string]linuxCmdResult{"iptables -L -n": cmdOK("Chain INPUT (policy DROP)\n")}, "iptables", true},
		{"iptables accept-all", map[string]linuxCmdResult{"iptables -L -n": cmdOK("Chain INPUT (policy ACCEPT)\n")}, "iptables", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stubLinuxSecurityCommands(t, c.cmds)
			got := collectFirewallProfiles()
			if len(got) != 1 || got[0].Name != c.want || got[0].Enabled != c.enabled {
				t.Errorf("got %+v, want %s enabled=%v", got, c.want, c.enabled)
			}
		})
	}
	t.Run("no firewall tooling", func(t *testing.T) {
		stubLinuxSecurityCommands(t, nil)
		if got := collectFirewallProfiles(); got != nil {
			t.Errorf("got %+v, want nil", got)
		}
		if anyFirewallEnabled(nil) {
			t.Error("anyFirewallEnabled(nil) = true")
		}
	})
}

func TestCollectAV(t *testing.T) {
	stubLinuxSecurityCommands(t, map[string]linuxCmdResult{
		"systemctl is-active clamav-daemon": cmdOK("active\n"),
		// Same product under a second unit name is reported once.
		"systemctl is-active clamd":         cmdOK("active\n"),
		"systemctl is-active falcon-sensor": cmdOK("inactive\n"),
		// Unexpected state text is not a detection.
		"systemctl is-active cbsensor": cmdOK("activating\n"),
		// Non-zero exit (unit not found) is not a detection.
		"systemctl is-active ds_agent": {out: "inactive\n", code: 4},
	})
	got := collectAV()
	if len(got) != 2 {
		t.Fatalf("got %+v, want ClamAV + CrowdStrike", got)
	}
	if got[0].Name != "ClamAV" || got[0].Enabled != "enabled" || got[0].Source != "service" || got[0].UpToDate != "unknown" {
		t.Errorf("ClamAV = %+v", got[0])
	}
	if got[1].Name != crowdStrikeFalconName || got[1].Enabled != "disabled" {
		t.Errorf("Falcon = %+v", got[1])
	}
}

func TestBuildAVProtection(t *testing.T) {
	root := stubLinuxSecurityRoot(t)
	writeRootFile(t, root, "/var/log/clamav/clamav.log",
		"Wed Oct  7 02:00:00 2026 -> ----------- SCAN SUMMARY -----------\n"+
			"Known viruses: 8700000\n"+
			"Scanned files: 1234\n"+
			"Infected files: 2\n")

	got := buildAVProtection([]shared.AntivirusProduct{
		{Name: "ClamAV", Enabled: "enabled"},
		{Name: "Sophos", Enabled: "disabled"},
		{Name: "Other", Enabled: "weird"},
	})
	if len(got.Products) != 3 {
		t.Fatalf("got %+v", got)
	}
	clam := got.Products[0]
	if clam.RealTimeProtectionState != "Enabled" || clam.ServiceStatus != "Running" || clam.ScanInfo == nil {
		t.Fatalf("ClamAV = %+v", clam)
	}
	scan := clam.ScanInfo
	if scan.LastScanTime != "Wed Oct  7 02:00:00 2026" || scan.ScannedFilesCount != 1234 ||
		scan.ScanResult != "Threats Detected" || len(scan.RecentThreats) != 1 {
		t.Errorf("scan = %+v", scan)
	}
	if got.Products[1].RealTimeProtectionState != "Disabled" || got.Products[1].ServiceStatus != "Stopped" ||
		got.Products[1].ScanInfo != nil {
		t.Errorf("Sophos = %+v", got.Products[1])
	}
	if got.Products[2].RealTimeProtectionState != "Unknown" {
		t.Errorf("Other = %+v", got.Products[2])
	}
}

func TestCollectClamAVScanInfo_NoLog(t *testing.T) {
	stubLinuxSecurityRoot(t)
	scan := collectClamAVScanInfo()
	if scan.LastScanTime != "Unknown" || scan.ScanResult != "Clean" || scan.ScanType != "Scheduled/On-Demand" {
		t.Errorf("scan = %+v", scan)
	}
}

func TestParseClamAVLogLine(t *testing.T) {
	var scan shared.SecurityScanInfo
	scan.ScanResult = "Clean"
	parseClamAVLogLine("Infected files: 0", &scan)
	parseClamAVLogLine("Scanned files: lots", &scan)
	parseClamAVLogLine("SCAN SUMMARY", &scan) // too short for a timestamp
	if scan.ScanResult != "Clean" || scan.ScannedFilesCount != 0 || scan.LastScanTime != "" {
		t.Errorf("scan = %+v", scan)
	}
	if _, ok := parseClamAVCount("no separator"); ok {
		t.Error("parseClamAVCount accepted a line without ':'")
	}
}

// clamscanLogTwoScans is a clamav.log holding two scans with clamd-style
// "<ctime> -> " prefixes: an older one (Oct 6, 500 files, 1 infected) and the
// newest one (Oct 7, 1234 files, 2 infected), followed by a clamd self-check.
const clamscanLogTwoScans = `Tue Oct  6 02:00:00 2026 -> +++ Started at Tue Oct  6 02:00:00 2026
Tue Oct  6 02:00:05 2026 -> /home/alice/Downloads/eicar.com: Eicar-Signature FOUND
Tue Oct  6 02:00:09 2026 -> ----------- SCAN SUMMARY -----------
Tue Oct  6 02:00:09 2026 -> Known viruses: 8700000
Tue Oct  6 02:00:09 2026 -> Engine version: 1.0.7
Tue Oct  6 02:00:09 2026 -> Scanned directories: 40
Tue Oct  6 02:00:09 2026 -> Scanned files: 500
Tue Oct  6 02:00:09 2026 -> Infected files: 1
Tue Oct  6 02:00:09 2026 -> Data scanned: 12.50 MB
Tue Oct  6 02:00:09 2026 -> Time: 9.012 sec (0 m 9 s)
Wed Oct  7 02:00:00 2026 -> +++ Started at Wed Oct  7 02:00:00 2026
Wed Oct  7 02:00:04 2026 -> /tmp/a/eicar.com: Eicar-Signature FOUND
Wed Oct  7 02:00:06 2026 -> /tmp/b/eicar.zip: Eicar-Signature FOUND
Wed Oct  7 02:00:11 2026 -> ----------- SCAN SUMMARY -----------
Wed Oct  7 02:00:11 2026 -> Known viruses: 8700000
Wed Oct  7 02:00:11 2026 -> Engine version: 1.0.7
Wed Oct  7 02:00:11 2026 -> Scanned directories: 41
Wed Oct  7 02:00:11 2026 -> Scanned files: 1234
Wed Oct  7 02:00:11 2026 -> Infected files: 2
Wed Oct  7 02:00:11 2026 -> Data scanned: 30.00 MB
Wed Oct  7 02:00:11 2026 -> Time: 11.204 sec (0 m 11 s)
Wed Oct  7 02:10:11 2026 -> SelfCheck: Database status OK.
`

// TestCollectClamAVScanInfo_NewestTimestampedScan is the regression test for
// issue #112: the newest summary must win, and timestamped count lines must
// parse the count after the label, not the time's minutes.
func TestCollectClamAVScanInfo_NewestTimestampedScan(t *testing.T) {
	root := stubLinuxSecurityRoot(t)
	writeRootFile(t, root, "/var/log/clamav/clamav.log", clamscanLogTwoScans)

	scan := collectClamAVScanInfo()
	if scan.LastScanTime != "Wed Oct  7 02:00:11 2026" {
		t.Errorf("LastScanTime = %q, want the newest summary's time", scan.LastScanTime)
	}
	if scan.ScannedFilesCount != 1234 {
		t.Errorf("ScannedFilesCount = %d, want 1234", scan.ScannedFilesCount)
	}
	if scan.ScanResult != "Threats Detected" || len(scan.RecentThreats) != 1 {
		t.Fatalf("ScanResult = %q, RecentThreats = %+v; want one threat entry from the newest scan",
			scan.ScanResult, scan.RecentThreats)
	}
	if scan.RecentThreats[0].DetectionTime != "Wed Oct  7 02:00:11 2026" {
		t.Errorf("DetectionTime = %q", scan.RecentThreats[0].DetectionTime)
	}
}

// TestCollectClamAVScanInfo_NewestScanClean: plain clamscan --log output (no
// timestamps) where an older scan found a threat but the newest is clean.
func TestCollectClamAVScanInfo_NewestScanClean(t *testing.T) {
	root := stubLinuxSecurityRoot(t)
	writeRootFile(t, root, "/var/log/clamav/clamav.log", `/home/alice/eicar.com: Eicar-Signature FOUND

----------- SCAN SUMMARY -----------
Known viruses: 8700000
Engine version: 1.0.7
Scanned directories: 40
Scanned files: 500
Infected files: 1
Data scanned: 12.50 MB
Start Date: 2026:10:06 02:00:00
End Date:   2026:10:06 02:00:09

----------- SCAN SUMMARY -----------
Known viruses: 8700000
Engine version: 1.0.7
Scanned directories: 41
Scanned files: 1234
Infected files: 0
Data scanned: 30.00 MB
Start Date: 2026:10:07 02:00:00
End Date:   2026:10:07 02:00:11
`)

	scan := collectClamAVScanInfo()
	if scan.ScannedFilesCount != 1234 {
		t.Errorf("ScannedFilesCount = %d, want 1234", scan.ScannedFilesCount)
	}
	if scan.ScanResult != "Clean" || len(scan.RecentThreats) != 0 {
		t.Errorf("ScanResult = %q, RecentThreats = %+v; want the newest (clean) scan only",
			scan.ScanResult, scan.RecentThreats)
	}
	if scan.LastScanTime != "Unknown" {
		t.Errorf("LastScanTime = %q, want Unknown for an untimestamped summary", scan.LastScanTime)
	}
}

func TestParseClamAVCount_Timestamped(t *testing.T) {
	got, ok := parseClamAVCount("Wed Oct  7 02:00:01 2026 -> Infected files: 2")
	if !ok || got != 2 {
		t.Errorf("parseClamAVCount = %d, %v; want 2, true", got, ok)
	}
}

func TestCollectEDRInfo(t *testing.T) {
	root := stubLinuxSecurityRoot(t)
	writeRootFile(t, root, "/proc/1/comm", "systemd\n")
	writeRootFile(t, root, "/proc/4242/comm", "wazuh-agentd\n")
	writeRootFile(t, root, "/proc/uptime", "12345.67 54321.00\n") // non-dir entry
	mkRootDir(t, root, "/proc/self")                              // non-numeric dir
	mkRootDir(t, root, "/proc/77")                                // exited between ReadDir and ReadFile

	stubLinuxSecurityCommands(t, map[string]linuxCmdResult{
		"systemctl is-active sentinelone":  cmdOK("active\n"),
		"systemctl is-enabled sentinelone": cmdOK("enabled\n"),
		"systemctl is-enabled osqueryd":    cmdOK("disabled\n"),
		"systemctl is-active velociraptor": cmdOK("failed\n"),
	})

	agents := map[string]shared.EDRXDRAgentDetails{}
	for _, a := range collectEDRInfo().Agents {
		agents[a.AgentName] = a
	}
	if len(agents) != 4 {
		t.Fatalf("agents = %+v", agents)
	}

	s1 := agents["SentinelOne Singularity"]
	if !s1.Running || !s1.Healthy || s1.Disabled || s1.ServiceStatus != "Running" || !s1.Installed {
		t.Errorf("SentinelOne = %+v", s1)
	}
	wz := agents["Wazuh Agent"] // detected via /proc only
	if !wz.Running || !wz.Healthy || wz.Disabled {
		t.Errorf("Wazuh = %+v", wz)
	}
	oq := agents["Osquery"]
	if oq.Running || !oq.Stopped || !oq.Disabled || !oq.Unhealthy || !oq.Offline || oq.HealthStatus != "Unhealthy" {
		t.Errorf("Osquery = %+v", oq)
	}
	vr := agents["Velociraptor"]
	if vr.Running || !vr.Stopped {
		t.Errorf("Velociraptor = %+v", vr)
	}
}

func TestRunningProcNames_NoProc(t *testing.T) {
	stubLinuxSecurityRoot(t)
	if got := runningProcNames(); len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

func TestCollectDeviceEncryption(t *testing.T) {
	cases := []struct {
		name string
		cmds map[string]linuxCmdResult
		want string
	}{
		{"LUKS present", map[string]linuxCmdResult{"lsblk -o NAME,FSTYPE": cmdOK("nvme0n1p3 crypto_LUKS\n")}, "Encrypted"},
		{"no LUKS", map[string]linuxCmdResult{"lsblk -o NAME,FSTYPE": cmdOK("sda1 ext4\n")}, "Unencrypted"},
		{"lsblk missing", nil, "Unencrypted"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stubLinuxSecurityCommands(t, c.cmds)
			if got := collectDeviceEncryption(); got.EncryptionStatus != c.want || got.RecoveryKeyBackupStatus != "Unknown" {
				t.Errorf("got %+v, want status %s", got, c.want)
			}
		})
	}
}

func TestCollectHardwareSecurity_TPM(t *testing.T) {
	cases := []struct {
		name        string
		files       map[string]string
		dirs        []string
		wantStatus  string
		wantVersion string
	}{
		{"no TPM", nil, nil, "Unsupported", "None"},
		{"TPM class without device", nil, []string{"/sys/class/tpm"}, "Disabled", "None"},
		{"TPM major version", map[string]string{"/dev/tpm0": "", "/sys/class/tpm/tpm0/tpm_version_major": "2\n"}, nil, "Enabled", "2.0"},
		{"TPM 2.0 description", map[string]string{"/dev/tpm0": "", "/sys/class/tpm/tpm0/device/description": "TPM 2.0 Device\n"}, nil, "Enabled", "2.0"},
		{"TPM other description", map[string]string{"/dev/tpm0": "", "/sys/class/tpm/tpm0/device/description": "TPM 1.2 Device\n"}, nil, "Enabled", "1.2"},
		{"TPM without version info", map[string]string{"/dev/tpm0": ""}, nil, "Enabled", "1.2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := stubLinuxSecurityRoot(t)
			stubLinuxSecurityCommands(t, nil)
			for p, content := range c.files {
				writeRootFile(t, root, p, content)
			}
			for _, d := range c.dirs {
				mkRootDir(t, root, d)
			}
			hw := collectHardwareSecurity()
			if hw.TPMStatus != c.wantStatus || hw.TPMVersion != c.wantVersion {
				t.Errorf("got status=%q version=%q, want %q %q", hw.TPMStatus, hw.TPMVersion, c.wantStatus, c.wantVersion)
			}
			if hw.SecureBootStatus != "unknown" || hw.SecureEnclaveStatus != "Unsupported" {
				t.Errorf("hw = %+v", hw)
			}
		})
	}
}

func TestCollectSecureBoot(t *testing.T) {
	cases := []struct {
		name string
		mok  *linuxCmdResult
		efi  []byte
		want string
	}{
		{"mokutil enabled", &linuxCmdResult{out: "SecureBoot enabled\n"}, nil, "enabled"},
		{"mokutil disabled", &linuxCmdResult{out: "SecureBoot disabled\nPlatform is in Setup Mode\n"}, nil, "disabled"},
		{"mokutil unclear, EFI var enabled", &linuxCmdResult{out: "EFI variables are not supported\n"}, []byte{6, 0, 0, 0, 1}, "enabled"},
		{"no mokutil, no EFI", nil, nil, "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := stubLinuxSecurityRoot(t)
			cmds := map[string]linuxCmdResult{}
			if c.mok != nil {
				cmds["mokutil --sb-state"] = *c.mok
			}
			stubLinuxSecurityCommands(t, cmds)
			if c.efi != nil {
				writeRootFile(t, root, "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", string(c.efi))
			}
			if got := collectSecureBoot(); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestCollectIdentityAccessControl_Defaults(t *testing.T) {
	stubLinuxSecurityRoot(t)
	stubLinuxSecurityCommands(t, nil)
	id := collectIdentityAccessControl()
	if id.SSHRootLogin != "Unknown" || id.SSHPasswordAuth != "Unknown" || id.SudoPrivilege != "Unknown" ||
		id.PendingSecurityPatches != 0 || id.PatchComplianceStatus != "Compliant" {
		t.Errorf("id = %+v", id)
	}
	net := collectNetworkExposure(nil, id)
	if net.SSHKeyAuthStatus != "Unknown" {
		t.Errorf("SSHKeyAuthStatus = %q", net.SSHKeyAuthStatus)
	}
}

func TestDetectSudoPrivilegeState(t *testing.T) {
	cases := map[string]string{
		"root:x:0:\nwheel:x:10:bob\n": "Configured",
		"root:x:0:\nusers:x:100:\n":   "Misconfigured",
		"sudo\n":                      "Misconfigured", // malformed line
	}
	for content, want := range cases {
		root := stubLinuxSecurityRoot(t)
		writeRootFile(t, root, "/etc/group", content)
		if got := detectSudoPrivilegeState(); got != want {
			t.Errorf("group %q: got %q, want %q", content, got, want)
		}
	}
}

func TestPendingSecurityPatchCount(t *testing.T) {
	const aptCheck = "/usr/lib/update-notifier/apt-check"
	const yumCmd = "yum check-update --security"
	cases := []struct {
		name  string
		files []string
		cmds  map[string]linuxCmdResult
		want  int
	}{
		{"no package manager", nil, nil, 0},
		// apt-check prints its "N;M" summary to stderr (no trailing newline)
		// and nothing to stdout; see issue #109.
		{"apt-check N;M on stderr", []string{aptCheck, "/usr/bin/apt-get"},
			map[string]linuxCmdResult{aptCheck: {stderr: "12;5"}}, 5},
		{"apt-check warning before N;M", []string{aptCheck},
			map[string]linuxCmdResult{aptCheck: {stderr: "/usr/lib/update-notifier/apt_check.py:9: " +
				"DeprecationWarning: deprecated\n  import apt_pkg\n12;5"}}, 5},
		{"apt-check error exit", []string{aptCheck},
			map[string]linuxCmdResult{aptCheck: {stderr: "E: Error: BrokenCount > 0", code: 255}}, 0},
		{"apt-check unparsable", []string{aptCheck}, map[string]linuxCmdResult{aptCheck: {stderr: "12;x"}}, 0},
		{"apt-check no separator", []string{aptCheck}, map[string]linuxCmdResult{aptCheck: cmdOK("")}, 0},
		{"apt-check fails", []string{aptCheck}, nil, 0},
		{"apt-get fails", []string{"/usr/bin/apt-get"}, nil, 0},
		{"yum updates available (exit 100)", []string{"/usr/bin/yum"},
			map[string]linuxCmdResult{yumCmd: {out: "kernel.x86_64  4.18.0-477  baseos-security\n", code: 100}}, 1},
		{"yum none (exit 0)", []string{"/usr/bin/yum"}, map[string]linuxCmdResult{yumCmd: cmdOK("\n")}, 0},
		{"yum error exit", []string{"/usr/bin/yum"},
			map[string]linuxCmdResult{yumCmd: {out: "kernel.x86_64 1-1 baseos-security\n", code: 1}}, 0},
		{"yum not runnable", []string{"/usr/bin/yum"}, nil, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := stubLinuxSecurityRoot(t)
			for _, f := range c.files {
				writeRootFile(t, root, f, "")
			}
			stubLinuxSecurityCommands(t, c.cmds)
			if got := pendingSecurityPatchCount(); got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}

func TestCollectUSBMassStorage(t *testing.T) {
	t.Run("module loaded", func(t *testing.T) {
		root := stubLinuxSecurityRoot(t)
		mkRootDir(t, root, "/sys/module/usb_storage")
		if got := collectUSBMassStorage(); got != "enabled" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("blacklisted", func(t *testing.T) {
		root := stubLinuxSecurityRoot(t)
		mkRootDir(t, root, "/etc/modprobe.d/subdir.conf") // directories are skipped
		writeRootFile(t, root, "/etc/modprobe.d/blacklist-usb.conf", "blacklist usb_storage\n")
		if got := collectUSBMassStorage(); got != "disabled" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("neither", func(t *testing.T) {
		stubLinuxSecurityRoot(t)
		if got := collectUSBMassStorage(); got != "unknown" {
			t.Errorf("got %q", got)
		}
	})
}

func TestCollectSELinux(t *testing.T) {
	cases := []struct {
		name    string
		enforce string
		sestat  string
		want    string
	}{
		{"enforce=1", "1\n", "", "enforcing"},
		{"enforce=0", "0\n", "", "permissive"},
		{"odd enforce falls back to sestatus", "2\n", "SELinux status: enabled\nCurrent mode: permissive\n", "permissive"},
		{"sestatus disabled", "", "SELinux status:                 disabled\n", "disabled"},
		{"sestatus unhelpful", "", "nothing useful\n", "unknown"},
		{"nothing available", "", "", "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := stubLinuxSecurityRoot(t)
			if c.enforce != "" {
				writeRootFile(t, root, "/sys/fs/selinux/enforce", c.enforce)
			}
			cmds := map[string]linuxCmdResult{}
			if c.sestat != "" {
				cmds["sestatus"] = cmdOK(c.sestat)
			}
			stubLinuxSecurityCommands(t, cmds)
			if got := collectSELinux(); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestCollectAppArmor(t *testing.T) {
	stubLinuxSecurityRoot(t)
	stubLinuxSecurityCommands(t, nil)
	if collectAppArmor() {
		t.Error("AppArmor reported without securityfs or aa-status")
	}
	stubLinuxSecurityCommands(t, map[string]linuxCmdResult{"aa-status --enabled": cmdOK("")})
	if !collectAppArmor() {
		t.Error("AppArmor not reported when aa-status --enabled succeeds")
	}
}

func TestCollectKernelLockdown(t *testing.T) {
	cases := map[string]string{
		"[none] integrity confidentiality\n": "none",
		"none integrity [confidentiality]\n": "confidentiality",
		"none integrity confidentiality\n":   "unknown",
	}
	for content, want := range cases {
		root := stubLinuxSecurityRoot(t)
		writeRootFile(t, root, "/sys/kernel/security/lockdown", content)
		if got := collectKernelLockdown(); got != want {
			t.Errorf("lockdown %q: got %q, want %q", content, got, want)
		}
	}
	stubLinuxSecurityRoot(t)
	if got := collectKernelLockdown(); got != "unknown" {
		t.Errorf("missing lockdown file: got %q", got)
	}
}

func TestSSHYesNoState_UnrecognisedValue(t *testing.T) {
	root, _, _ := parseSSHConfigData("PermitRootLogin forced-commands-only\n")
	if root != "Unknown" {
		t.Errorf("forced-commands-only: got %q, want Unknown", root)
	}
}
