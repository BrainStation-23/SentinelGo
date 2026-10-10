package security

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

// Command keys ("name arg1 arg2 ...") for every probe in security_darwin.go.
const (
	darwinCmdSocketFW  = "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
	darwinCmdCsrutil   = "csrutil status"
	darwinCmdIBridge   = "system_profiler SPiBridgeDataType"
	darwinCmdHardware  = "system_profiler SPHardwareDataType"
	darwinCmdSpctl     = "spctl --status"
	darwinCmdPlutil    = "plutil -convert json -o - /Library/Managed Preferences/com.apple.applicationaccess.plist"
	darwinCmdKextstat  = "kextstat"
	darwinCmdPs        = "ps -axco comm"
	darwinCmdFdeStatus = "fdesetup status"
	darwinCmdFdeKey    = "fdesetup haspersonalrecoverykey"
	darwinCmdBioutil   = "bioutil -read -system"
	darwinCmdProfiles  = "profiles status -type bootstraptoken"
	darwinCmdSecToken  = "sysadminctl -secureTokenStatus "
	darwinCmdSWUpdate  = "softwareupdate -l"
	darwinCmdXProtect1 = "defaults read /System/Library/CoreServices/XProtect.bundle/Contents/Info CFBundleShortVersionString"
	darwinCmdXProtect2 = "defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info CFBundleShortVersionString"

	darwinMRTPath1 = "/System/Library/CoreServices/MRT.app"
	darwinMRTPath2 = "/Library/Apple/System/Library/CoreServices/MRT.app"
	darwinMRTLog   = "/var/log/MRT.log"
)

// stubDarwinSecurityCommands replaces darwinRunCommand and
// darwinRunCommandOutput for the duration of the test. Keys in responses
// return their output (from either runner); every other command fails. The
// returned pointer records every command that was run. Use
// stubDarwinProcesses when stdout and stderr must be told apart.
func stubDarwinSecurityCommands(t *testing.T, responses map[string]string) *[]string {
	t.Helper()
	orig, origOut := darwinRunCommand, darwinRunCommandOutput
	var calls []string
	darwinRunCommand = func(name string, args ...string) (string, error) {
		key := strings.Join(append([]string{name}, args...), " ")
		calls = append(calls, key)
		if out, ok := responses[key]; ok {
			return out, nil
		}
		return "", errors.New("command failed: " + key)
	}
	darwinRunCommandOutput = func(name string, args ...string) (string, int, error) {
		key := strings.Join(append([]string{name}, args...), " ")
		calls = append(calls, key)
		if out, ok := responses[key]; ok {
			return out, 0, nil
		}
		return "", -1, errors.New("command failed: " + key)
	}
	t.Cleanup(func() { darwinRunCommand, darwinRunCommandOutput = orig, origOut })
	return &calls
}

// stubDarwinSecurityFS replaces darwinStat and darwinReadFile for the
// duration of the test: only paths in existing stat successfully, and only
// paths in files can be read.
func stubDarwinSecurityFS(t *testing.T, existing []string, files map[string]string) {
	t.Helper()
	origStat, origRead := darwinStat, darwinReadFile
	exists := make(map[string]bool, len(existing))
	for _, p := range existing {
		exists[p] = true
	}
	darwinStat = func(name string) (os.FileInfo, error) {
		if exists[name] {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
	darwinReadFile = func(name string) ([]byte, error) {
		if c, ok := files[name]; ok {
			return []byte(c), nil
		}
		return nil, os.ErrNotExist
	}
	t.Cleanup(func() { darwinStat, darwinReadFile = origStat, origRead })
}

func ranCommand(calls []string, key string) bool {
	for _, c := range calls {
		if c == key {
			return true
		}
	}
	return false
}

func TestParseAllowUSBRestrictedJSON(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"allowed true → enabled", `{"allowUSBRestricted":true}`, "enabled"},
		{"allowed false → disabled", `{"allowUSBRestricted":false}`, "disabled"},
		{"key absent → empty", `{"otherKey":true}`, ""},
		{"empty object → empty", `{}`, ""},
		{"invalid json → empty", `not json`, ""},
		{"wrong value type → empty", `{"allowUSBRestricted":"yes"}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseAllowUSBRestrictedJSON(c.input)
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestKnownAVApps(t *testing.T) {
	for _, app := range knownAVApps {
		if app.path == "" {
			t.Errorf("empty path for AV app %q", app.name)
		}
		if app.name == "" {
			t.Errorf("empty name for AV path %q", app.path)
		}
	}
}

func TestCollectSecureBoot(t *testing.T) {
	cases := []struct {
		name   string
		output *string
		want   string
	}{
		{"full security", strRef("Boot Policy: Full Security"), "enabled"},
		{"reduced security", strRef("Boot Policy: Reduced Security"), "enabled"},
		{"no security", strRef("Boot Policy: No Security"), "disabled"},
		{"T2 without policy line", strRef("Apple T2 Security Chip\n  Bridge OS Version: 17.4"), "enabled"},
		{"Intel Mac without T2", strRef("Intel Mac without T2"), "unknown"},
		{"empty output", strRef(""), "unknown"},
		{"command fails", nil, "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			responses := map[string]string{}
			if c.output != nil {
				responses[darwinCmdIBridge] = *c.output
			}
			stubDarwinSecurityCommands(t, responses)
			if got := collectSecureBoot(); got != c.want {
				t.Errorf("collectSecureBoot() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestCollectSIP(t *testing.T) {
	cases := []struct {
		name   string
		output *string
		want   string
	}{
		{"enabled", strRef("System Integrity Protection status: enabled.\n"), "enabled"},
		{"disabled", strRef("System Integrity Protection status: disabled.\n"), "disabled"},
		{"neither", strRef("System Integrity Protection status: unknown (Custom Configuration).\n"), "unknown"},
		{"empty", strRef(""), "unknown"},
		{"command fails", nil, "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			responses := map[string]string{}
			if c.output != nil {
				responses[darwinCmdCsrutil] = *c.output
			}
			stubDarwinSecurityCommands(t, responses)
			if got := collectSIP(); got != c.want {
				t.Errorf("collectSIP() = %q, want %q", got, c.want)
			}
			if got := collectCoreIsolation().SIPEnabled; got != c.want {
				t.Errorf("collectCoreIsolation().SIPEnabled = %q, want %q", got, c.want)
			}
		})
	}
}

func TestAnyFirewallEnabled(t *testing.T) {
	cases := []struct {
		name     string
		profiles []shared.FirewallProfile
		want     bool
	}{
		{"nil", nil, false},
		{"all disabled", []shared.FirewallProfile{{Name: "a"}, {Name: "b"}}, false},
		{"one enabled", []shared.FirewallProfile{{Name: "a"}, {Name: "b", Enabled: true}}, true},
	}
	for _, c := range cases {
		if got := anyFirewallEnabled(c.profiles); got != c.want {
			t.Errorf("%s: anyFirewallEnabled() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCollectFirewallProfiles(t *testing.T) {
	cases := []struct {
		name   string
		output *string
		want   []shared.FirewallProfile
	}{
		{"enabled", strRef("Firewall is enabled. (State = 1)\n"),
			[]shared.FirewallProfile{{Name: "Application Firewall", Enabled: true}}},
		{"disabled", strRef("Firewall is disabled. (State = 0)\n"),
			[]shared.FirewallProfile{{Name: "Application Firewall", Enabled: false}}},
		{"command fails", nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			responses := map[string]string{}
			if c.output != nil {
				responses[darwinCmdSocketFW] = *c.output
			}
			stubDarwinSecurityCommands(t, responses)
			if got := collectFirewallProfiles(); !reflect.DeepEqual(got, c.want) {
				t.Errorf("collectFirewallProfiles() = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestBuildAVProtection(t *testing.T) {
	if got := buildAVProtection(nil); got.Products != nil {
		t.Errorf("buildAVProtection(nil).Products = %+v, want nil", got.Products)
	}

	got := buildAVProtection([]shared.AntivirusProduct{
		{Name: "Malwarebytes", Enabled: "unknown"},
		{Name: "Gatekeeper", Enabled: "enabled"},
		{Name: "Other", Enabled: "DISABLED"},
	})
	base := func(name, rtp, svc string) shared.AntivirusDetails {
		return shared.AntivirusDetails{
			ProductName: name, Vendor: "Unknown", Version: "Unknown",
			RealTimeProtectionState: rtp, ServiceStatus: svc, UpdateStatus: "Unknown",
		}
	}
	want := []shared.AntivirusDetails{
		base("Malwarebytes", "Unknown", "Unknown"),
		base("Gatekeeper", "Enabled", "Running"),
		base("Other", "Disabled", "Stopped"),
	}
	if !reflect.DeepEqual(got.Products, want) {
		t.Errorf("Products =\n  %+v\nwant\n  %+v", got.Products, want)
	}
}

func TestDetectXProtectVersion(t *testing.T) {
	cases := []struct {
		name      string
		responses map[string]string
		want      string
	}{
		{"primary location", map[string]string{darwinCmdXProtect1: "2178\n", darwinCmdXProtect2: "9999\n"}, "2178"},
		{"fallback location", map[string]string{darwinCmdXProtect2: "  5299 \n"}, "5299"},
		{"neither readable", map[string]string{}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stubDarwinSecurityCommands(t, c.responses)
			if got := detectXProtectVersion(); got != c.want {
				t.Errorf("detectXProtectVersion() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestDetectMRTInstalled(t *testing.T) {
	cases := []struct {
		name     string
		existing []string
		want     bool
	}{
		{"absent", nil, false},
		{"primary location", []string{darwinMRTPath1}, true},
		{"fallback location", []string{darwinMRTPath2}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stubDarwinSecurityFS(t, c.existing, nil)
			if got := detectMRTInstalled(); got != c.want {
				t.Errorf("detectMRTInstalled() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestCollectMRTScanInfo(t *testing.T) {
	threat := shared.ThreatDetails{
		ThreatName:    "Malware",
		Severity:      "High",
		FilePath:      "Check /var/log/MRT.log",
		ActionTaken:   "Removed",
		DetectionTime: "2024-03-04 05:06:07",
	}
	cases := []struct {
		name string
		log  *string
		want shared.SecurityScanInfo
	}{
		{
			name: "log missing",
			log:  nil,
			want: shared.SecurityScanInfo{LastScanTime: "Unknown", ScanType: "On-Access", ScanResult: "Clean"},
		},
		{
			name: "empty log",
			log:  strRef(""),
			want: shared.SecurityScanInfo{LastScanTime: "Unknown", ScanType: "On-Access", ScanResult: "Clean"},
		},
		{
			name: "clean scan uses last non-empty line",
			log:  strRef("2024-01-01 10:00:00 MRT removed OSX.Old\n2024-01-02 11:22:33 MRT finished scan\n\n   \n"),
			want: shared.SecurityScanInfo{LastScanTime: "2024-01-02 11:22:33", ScanType: "On-Access", ScanResult: "Clean"},
		},
		{
			name: "threat removed on last line",
			log:  strRef("2024-03-04 05:00:00 MRT started\n2024-03-04 05:06:07 Removing OSX.Foo from /tmp/x\n"),
			want: shared.SecurityScanInfo{
				LastScanTime:  "2024-03-04 05:06:07",
				ScanType:      "On-Access",
				ScanResult:    "Threats Detected",
				RecentThreats: []shared.ThreatDetails{threat},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{}
			if c.log != nil {
				files[darwinMRTLog] = *c.log
			}
			stubDarwinSecurityFS(t, nil, files)
			if got := collectMRTScanInfo(); !reflect.DeepEqual(got, c.want) {
				t.Errorf("collectMRTScanInfo() =\n  %+v\nwant\n  %+v", got, c.want)
			}
		})
	}
}

func TestParseMRTLogLine_SingleToken(t *testing.T) {
	scan := shared.SecurityScanInfo{LastScanTime: "Unknown", ScanResult: "Clean"}
	parseMRTLogLine("REMOVED", &scan)
	if scan.LastScanTime != "Unknown" {
		t.Errorf("LastScanTime = %q, want %q (no timestamp fields)", scan.LastScanTime, "Unknown")
	}
	if scan.ScanResult != "Threats Detected" {
		t.Errorf("ScanResult = %q, want %q", scan.ScanResult, "Threats Detected")
	}
	if len(scan.RecentThreats) != 1 || scan.RecentThreats[0].DetectionTime != "Unknown" {
		t.Errorf("RecentThreats = %+v, want one threat detected at %q", scan.RecentThreats, "Unknown")
	}
}

func TestBuildMRTDetails(t *testing.T) {
	stubDarwinSecurityFS(t, nil, map[string]string{darwinMRTLog: "2024-05-06 07:08:09 MRT scan complete\n"})
	got := buildMRTDetails()
	if got.ProductName != "Malware Removal Tool" || got.Vendor != "Apple" || got.Version != "Unknown" ||
		got.RealTimeProtectionState != "Enabled" || got.ServiceStatus != "Running" || got.UpdateStatus != "Unknown" {
		t.Errorf("buildMRTDetails() = %+v", got)
	}
	if got.ScanInfo == nil {
		t.Fatal("ScanInfo is nil")
	}
	if got.ScanInfo.LastScanTime != "2024-05-06 07:08:09" || got.ScanInfo.ScanResult != "Clean" {
		t.Errorf("ScanInfo = %+v", *got.ScanInfo)
	}
}

func TestCollectEDRInfo(t *testing.T) {
	t.Run("nothing installed and ps fails", func(t *testing.T) {
		stubDarwinSecurityCommands(t, nil)
		stubDarwinSecurityFS(t, nil, nil)
		if got := collectEDRInfo(); got.Agents != nil {
			t.Errorf("Agents = %+v, want nil", got.Agents)
		}
	})

	t.Run("detected by process and by path", func(t *testing.T) {
		stubDarwinSecurityCommands(t, map[string]string{
			darwinCmdPs: "COMM\nlaunchd\n  falcon-sensor  \nsentineld\n",
		})
		stubDarwinSecurityFS(t, []string{"/usr/local/bin/velociraptor", "/var/db/osquery"}, nil)

		got := collectEDRInfo().Agents

		type summary struct {
			Name, Vendor, Service, Health                string
			Installed, Running, Stopped, Healthy, Unheal bool
			Offline                                      bool
		}
		var gotSum []summary
		for _, a := range got {
			if a.AgentVersion != "Unknown" || a.ConnectivityStatus != "Unknown" || a.TamperProtectionStatus != "Unknown" {
				t.Errorf("agent %q has unexpected placeholder fields: %+v", a.AgentName, a)
			}
			gotSum = append(gotSum, summary{
				a.AgentName, a.Vendor, a.ServiceStatus, a.HealthStatus,
				a.Installed, a.Running, a.Stopped, a.Healthy, a.Unhealthy, a.Offline,
			})
		}
		want := []summary{
			{"CrowdStrike Falcon", "CrowdStrike", "Running", "Healthy", true, true, false, true, false, false},
			{"SentinelOne Singularity", "SentinelOne", "Running", "Healthy", true, true, false, true, false, false},
			{"Velociraptor", "Velociraptor", "Stopped", "Unhealthy", true, false, true, false, true, true},
			{"Osquery", "Osquery", "Stopped", "Unhealthy", true, false, true, false, true, true},
		}
		if !reflect.DeepEqual(gotSum, want) {
			t.Errorf("agents =\n  %+v\nwant\n  %+v", gotSum, want)
		}
	})
}

func TestCollectDeviceEncryption(t *testing.T) {
	cases := []struct {
		name      string
		responses map[string]string
		want      shared.DeviceEncryptionInfo
		wantKeyQ  bool
	}{
		{
			name:      "fdesetup fails",
			responses: map[string]string{darwinCmdFdeKey: "true\n"},
			want: shared.DeviceEncryptionInfo{
				EncryptionProvider: "None", EncryptionStatus: "Unencrypted",
				ProtectionStatus: "Disabled", RecoveryKeyBackupStatus: "Unknown",
			},
			wantKeyQ: false,
		},
		{
			name:      "FileVault on with personal recovery key",
			responses: map[string]string{darwinCmdFdeStatus: "FileVault is On.\n", darwinCmdFdeKey: "true\n"},
			want: shared.DeviceEncryptionInfo{
				EncryptionProvider: "FileVault", EncryptionStatus: "Encrypted",
				ProtectionStatus: "Enabled", RecoveryKeyBackupStatus: "Backed Up",
			},
			wantKeyQ: true,
		},
		{
			name:      "FileVault on, recovery key query fails",
			responses: map[string]string{darwinCmdFdeStatus: "FileVault is On.\n"},
			want: shared.DeviceEncryptionInfo{
				EncryptionProvider: "FileVault", EncryptionStatus: "Encrypted",
				ProtectionStatus: "Enabled", RecoveryKeyBackupStatus: "Unknown",
			},
			wantKeyQ: true,
		},
		{
			name:      "FileVault off, no recovery key",
			responses: map[string]string{darwinCmdFdeStatus: "FileVault is Off.\n", darwinCmdFdeKey: "false\n"},
			want: shared.DeviceEncryptionInfo{
				EncryptionProvider: "None", EncryptionStatus: "Unencrypted",
				ProtectionStatus: "Disabled", RecoveryKeyBackupStatus: "Unknown",
			},
			wantKeyQ: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			calls := stubDarwinSecurityCommands(t, c.responses)
			if got := collectDeviceEncryption(); !reflect.DeepEqual(got, c.want) {
				t.Errorf("collectDeviceEncryption() = %+v, want %+v", got, c.want)
			}
			if ran := ranCommand(*calls, darwinCmdFdeKey); ran != c.wantKeyQ {
				t.Errorf("recovery key queried = %v, want %v", ran, c.wantKeyQ)
			}
		})
	}
}

func TestCollectHardwareSecurity(t *testing.T) {
	cases := []struct {
		name                          string
		responses                     map[string]string
		wantEnclave, wantLock, wantSB string
	}{
		{
			name: "Apple Silicon",
			responses: map[string]string{
				darwinCmdHardware: "Hardware:\n\n    Hardware Overview:\n\n      Model Name: MacBook Pro\n      Chip: Apple M2 Pro\n      Activation Lock Status: Disabled\n",
				darwinCmdIBridge:  "Boot Policy: Full Security\n",
			},
			wantEnclave: "Enabled", wantLock: "Disabled", wantSB: "enabled",
		},
		{
			name: "Intel with T2",
			responses: map[string]string{
				// SPHardwareDataType does not name the T2; SPiBridgeDataType does.
				darwinCmdHardware: "Model Name: MacBook Pro\n  Processor Name: Quad-Core Intel Core i7\n",
				darwinCmdIBridge:  "Controller Information:\n  Model Name: Apple T2 Security Chip\n  Boot Policy: No Security\n",
			},
			wantEnclave: "Enabled", wantLock: "Unknown", wantSB: "disabled",
		},
		{
			name: "Intel without T2",
			responses: map[string]string{
				darwinCmdHardware: "Hardware Overview:\n  Model Name: iMac\n  Processor Name: 6-Core Intel Core i5\n  Activation Lock Status: Enabled\n",
			},
			wantEnclave: "Unsupported", wantLock: "Enabled", wantSB: "unknown",
		},
		{
			name:        "system_profiler fails",
			responses:   map[string]string{},
			wantEnclave: "Unsupported", wantLock: "Unknown", wantSB: "unknown",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stubDarwinSecurityCommands(t, c.responses)
			got := collectHardwareSecurity()
			if got.TPMStatus != "Unsupported" || got.TPMVersion != "None" {
				t.Errorf("TPM = %q/%q, want Unsupported/None", got.TPMStatus, got.TPMVersion)
			}
			if got.SecureEnclaveStatus != c.wantEnclave {
				t.Errorf("SecureEnclaveStatus = %q, want %q", got.SecureEnclaveStatus, c.wantEnclave)
			}
			if got.ActivationLockStatus != c.wantLock {
				t.Errorf("ActivationLockStatus = %q, want %q", got.ActivationLockStatus, c.wantLock)
			}
			if got.SecureBootStatus != c.wantSB {
				t.Errorf("SecureBootStatus = %q, want %q", got.SecureBootStatus, c.wantSB)
			}
		})
	}
}

func TestCollectIdentityAccessControl(t *testing.T) {
	type want struct {
		touchID, bootstrap, secureToken, patch, rsr string
	}
	cases := []struct {
		name          string
		user, logname string
		responses     map[string]string
		want          want
		wantTokenCmd  string // "" means sysadminctl must not run
	}{
		{
			name: "everything enabled, rapid security response pending",
			user: "alice",
			responses: map[string]string{
				darwinCmdBioutil:            "System Touch ID configuration:\n\tTouch ID functionality: 1\n\tTouch ID for unlock: 1\n",
				darwinCmdProfiles:           "profiles: Bootstrap Token supported on server: YES\nprofiles: Bootstrap Token escrowed to server: YES\n",
				darwinCmdSecToken + "alice": "Secure token is ENABLED for user alice\n",
				darwinCmdSWUpdate:           "* Label: macOS Ventura 13.3.1 (a)\n\tTitle: Rapid Security Response macOS 13.3.1 (a), Recommended: YES, Action: restart,\n",
			},
			want:         want{"Enabled", "Enabled", "Enabled", "Non-Compliant", "Out of Date"},
			wantTokenCmd: darwinCmdSecToken + "alice",
		},
		{
			name:    "LOGNAME fallback, secure token disabled, all else fails",
			user:    "",
			logname: "svc",
			responses: map[string]string{
				darwinCmdSecToken + "svc": "Secure token is DISABLED for user svc\n",
			},
			want:         want{"Disabled", "Disabled", "Disabled", "Compliant", "Up to Date"},
			wantTokenCmd: darwinCmdSecToken + "svc",
		},
		{
			name: "no user: secure token not queried; ordinary security update",
			responses: map[string]string{
				darwinCmdBioutil:  "System Touch ID configuration:\n\tTouch ID functionality: 1\n\tTouch ID for unlock: 0\n",
				darwinCmdProfiles: "profiles: Bootstrap Token supported on server: YES\nprofiles: Bootstrap Token escrowed to server: YES\n",
				darwinCmdSWUpdate: "* Label: Security Update 2024-001\n",
			},
			want: want{"Disabled", "Enabled", "Unknown", "Non-Compliant", "Up to Date"},
		},
		{
			name: "unrecognised secure token output; non-security update",
			user: "bob",
			responses: map[string]string{
				darwinCmdSecToken + "bob": "something unexpected\n",
				darwinCmdSWUpdate:         "* Label: Safari17.4\n\tTitle: Safari, Version: 17.4, Recommended: YES,\n",
			},
			want:         want{"Disabled", "Disabled", "Unknown", "Compliant", "Up to Date"},
			wantTokenCmd: darwinCmdSecToken + "bob",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("USER", c.user)
			t.Setenv("LOGNAME", c.logname)
			calls := stubDarwinSecurityCommands(t, c.responses)

			id := collectIdentityAccessControl()
			got := want{id.TouchIDStatus, id.BootstrapTokenStatus, id.SecureTokenStatus,
				id.PatchComplianceStatus, id.RapidSecurityResponses}
			if got != c.want {
				t.Errorf("got %+v, want %+v", got, c.want)
			}

			var tokenCmds []string
			for _, cmd := range *calls {
				if strings.HasPrefix(cmd, darwinCmdSecToken) {
					tokenCmds = append(tokenCmds, cmd)
				}
			}
			switch {
			case c.wantTokenCmd == "" && len(tokenCmds) != 0:
				t.Errorf("sysadminctl ran %q, want not run", tokenCmds)
			case c.wantTokenCmd != "" && !reflect.DeepEqual(tokenCmds, []string{c.wantTokenCmd}):
				t.Errorf("sysadminctl ran %q, want [%q]", tokenCmds, c.wantTokenCmd)
			}
		})
	}
}

func TestCollectAV(t *testing.T) {
	gatekeeper := func(enabled string) shared.AntivirusProduct {
		return shared.AntivirusProduct{Name: "Gatekeeper", Enabled: enabled, UpToDate: "unknown", Source: "gatekeeper"}
	}
	process := func(name string) shared.AntivirusProduct {
		return shared.AntivirusProduct{Name: name, Enabled: "unknown", UpToDate: "unknown", Source: "process"}
	}
	cases := []struct {
		name      string
		existing  []string
		responses map[string]string
		want      []shared.AntivirusProduct
	}{
		{
			name: "duplicate product paths are reported once",
			existing: []string{
				"/Applications/Falcon.app",
				"/Library/CS/falconctl",
				"/Library/Sophos Anti-Virus Extension",
			},
			responses: map[string]string{darwinCmdSpctl: "assessments enabled\n"},
			want:      []shared.AntivirusProduct{process(avCrowdStrikeFalcon), process("Sophos AV"), gatekeeper("enabled")},
		},
		{
			name:      "gatekeeper disabled",
			responses: map[string]string{darwinCmdSpctl: "assessments disabled\n"},
			want:      []shared.AntivirusProduct{gatekeeper("disabled")},
		},
		{
			name:      "spctl fails",
			existing:  []string{"/Applications/Malwarebytes.app"},
			responses: map[string]string{},
			want:      []shared.AntivirusProduct{process("Malwarebytes"), gatekeeper("disabled")},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stubDarwinSecurityCommands(t, c.responses)
			stubDarwinSecurityFS(t, c.existing, nil)
			if got := collectAV(); !reflect.DeepEqual(got, c.want) {
				t.Errorf("collectAV() =\n  %+v\nwant\n  %+v", got, c.want)
			}
		})
	}
}

func TestCollectUSBMassStorage(t *testing.T) {
	cases := []struct {
		name         string
		responses    map[string]string
		want         string
		wantKextstat bool
	}{
		{
			name:         "MDM policy restricts USB",
			responses:    map[string]string{darwinCmdPlutil: `{"allowUSBRestricted":false}`, darwinCmdKextstat: "IOUSBMassStorageClass"},
			want:         "disabled",
			wantKextstat: false,
		},
		{
			name:         "MDM policy allows USB",
			responses:    map[string]string{darwinCmdPlutil: `{"allowUSBRestricted":true}`},
			want:         "enabled",
			wantKextstat: false,
		},
		{
			name:         "no MDM plist, mass storage kext loaded",
			responses:    map[string]string{darwinCmdKextstat: "  42  0 0xffffff7f8 com.apple.iokit.IOUSBMassStorageClass (4.0.4)\n"},
			want:         "enabled",
			wantKextstat: true,
		},
		{
			name:         "MDM plist without key, kext not loaded",
			responses:    map[string]string{darwinCmdPlutil: `{}`, darwinCmdKextstat: "com.apple.kpi.bsd\n"},
			want:         "unknown",
			wantKextstat: true,
		},
		{
			name:         "everything fails",
			responses:    map[string]string{},
			want:         "unknown",
			wantKextstat: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			calls := stubDarwinSecurityCommands(t, c.responses)
			if got := collectUSBMassStorage(); got != c.want {
				t.Errorf("collectUSBMassStorage() = %q, want %q", got, c.want)
			}
			if ran := ranCommand(*calls, darwinCmdKextstat); ran != c.wantKextstat {
				t.Errorf("kextstat ran = %v, want %v", ran, c.wantKextstat)
			}
		})
	}
}

// TestCollect_DarwinStubbed drives the whole macOS collector with canned
// command output and a fake filesystem. Listening ports still come from the
// real host via gopsutil, so nothing derived from them is asserted.
func TestCollect_DarwinStubbed(t *testing.T) {
	t.Setenv("USER", "")
	t.Setenv("LOGNAME", "")
	stubDarwinSecurityCommands(t, map[string]string{
		darwinCmdSocketFW:  "Firewall is enabled. (State = 1)\n",
		darwinCmdCsrutil:   "System Integrity Protection status: enabled.\n",
		darwinCmdIBridge:   "Boot Policy: Full Security\n",
		darwinCmdHardware:  "Chip: Apple M1\nActivation Lock Status: Disabled\n",
		darwinCmdSpctl:     "assessments enabled\n",
		darwinCmdPlutil:    `{"allowUSBRestricted":false}`,
		darwinCmdPs:        "launchd\n",
		darwinCmdFdeStatus: "FileVault is On.\n",
		darwinCmdFdeKey:    "true\n",
		darwinCmdXProtect1: "5299\n",
	})
	stubDarwinSecurityFS(t,
		[]string{darwinMRTPath1},
		map[string]string{darwinMRTLog: "2024-05-06 07:08:09 MRT scan complete\n"})

	info := Collect()

	if !info.FirewallEnabled {
		t.Error("FirewallEnabled = false, want true")
	}
	if want := []shared.FirewallProfile{{Name: "Application Firewall", Enabled: true}}; !reflect.DeepEqual(info.FirewallProfiles, want) {
		t.Errorf("FirewallProfiles = %+v, want %+v", info.FirewallProfiles, want)
	}
	wantAV := []shared.AntivirusProduct{{Name: "Gatekeeper", Enabled: "enabled", UpToDate: "unknown", Source: "gatekeeper"}}
	if !reflect.DeepEqual(info.AntivirusProducts, wantAV) {
		t.Errorf("AntivirusProducts = %+v, want %+v", info.AntivirusProducts, wantAV)
	}
	if info.CoreIsolation.SIPEnabled != "enabled" {
		t.Errorf("CoreIsolation.SIPEnabled = %q, want enabled", info.CoreIsolation.SIPEnabled)
	}
	if info.SecureBootEnabled != "enabled" {
		t.Errorf("SecureBootEnabled = %q, want enabled", info.SecureBootEnabled)
	}
	if info.USBMassStorageEnabled != "disabled" {
		t.Errorf("USBMassStorageEnabled = %q, want disabled", info.USBMassStorageEnabled)
	}
	wantKH := shared.KernelHardeningInfo{SIPEnabled: "enabled", USBMassStorageEnabled: "disabled"}
	if !reflect.DeepEqual(info.KernelHardening, wantKH) {
		t.Errorf("KernelHardening = %+v, want %+v", info.KernelHardening, wantKH)
	}

	av := info.AntivirusProtection
	if av.XProtectVersion != "5299" {
		t.Errorf("XProtectVersion = %q, want 5299", av.XProtectVersion)
	}
	if !av.MRTInstalled {
		t.Error("MRTInstalled = false, want true")
	}
	if len(av.Products) != 2 {
		t.Fatalf("AntivirusProtection.Products = %+v, want Gatekeeper + MRT", av.Products)
	}
	if av.Products[0].ProductName != "Gatekeeper" || av.Products[0].RealTimeProtectionState != "Enabled" {
		t.Errorf("Products[0] = %+v, want enabled Gatekeeper", av.Products[0])
	}
	if av.Products[1].ProductName != "Malware Removal Tool" || av.Products[1].ScanInfo == nil ||
		av.Products[1].ScanInfo.LastScanTime != "2024-05-06 07:08:09" {
		t.Errorf("Products[1] = %+v, want MRT with scan time from log", av.Products[1])
	}

	if len(info.EDRXDRDetection.Agents) != 0 {
		t.Errorf("EDR agents = %+v, want none", info.EDRXDRDetection.Agents)
	}
	if info.DeviceEncryption.EncryptionProvider != "FileVault" || info.DeviceEncryption.RecoveryKeyBackupStatus != "Backed Up" {
		t.Errorf("DeviceEncryption = %+v", info.DeviceEncryption)
	}
	hw := info.HardwareSecurity
	if hw.SecureEnclaveStatus != "Enabled" || hw.ActivationLockStatus != "Disabled" || hw.SecureBootStatus != "enabled" {
		t.Errorf("HardwareSecurity = %+v", hw)
	}
	id := info.IdentityAccessControl
	if id.SecureTokenStatus != "Unknown" || id.PatchComplianceStatus != "Compliant" || id.TouchIDStatus != "Disabled" {
		t.Errorf("IdentityAccessControl = %+v", id)
	}
}

func strRef(s string) *string { return &s }
