package security

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Regression tests for issues #110 and #118. The fixtures are realistic
// macOS command output gathered from published admin scripts and vendor docs
// (see the comments on each fixture); they replace the guessed formats the
// original parsing was written against.

// fakeProc models one invocation of an external command: what it writes to
// stdout and stderr and how it exits.
type fakeProc struct {
	stdout, stderr string
	exit           int
}

// stubDarwinProcesses replaces both command seams with fakes that keep stdout
// and stderr apart the way the real runners do: darwinRunCommand
// (shared.RunCommand, exec.Cmd.Output) sees only stdout and fails on a
// non-zero exit; darwinRunCommandOutput (shared.RunCommandOutput,
// exec.Cmd.CombinedOutput) sees stdout and stderr and reports the exit code
// without an error. Commands not in procs fail to start.
func stubDarwinProcesses(t *testing.T, procs map[string]fakeProc) {
	t.Helper()
	orig, origOut := darwinRunCommand, darwinRunCommandOutput
	darwinRunCommand = func(name string, args ...string) (string, error) {
		key := strings.Join(append([]string{name}, args...), " ")
		p, ok := procs[key]
		if !ok {
			return "", errors.New("exec: not found: " + key)
		}
		if p.exit != 0 {
			return "", fmt.Errorf("exit status %d", p.exit)
		}
		return p.stdout, nil
	}
	darwinRunCommandOutput = func(name string, args ...string) (string, int, error) {
		key := strings.Join(append([]string{name}, args...), " ")
		p, ok := procs[key]
		if !ok {
			return "", -1, errors.New("exec: not found: " + key)
		}
		return p.stdout + p.stderr, p.exit, nil
	}
	t.Cleanup(func() { darwinRunCommand, darwinRunCommandOutput = orig, origOut })
}

// Issue #110 (1): `profiles status -type bootstraptoken` prints
// "profiles: Bootstrap Token supported on server: YES" and
// "profiles: Bootstrap Token escrowed to server: YES" on stdout (FileWave KB
// also shows "escrowed on server"). Only an escrowed token counts as Enabled:
// server support alone does not put a token on the server.
func TestCollectIdentityAccessControl_BootstrapTokenRealOutput(t *testing.T) {
	cases := []struct {
		name, stdout, want string
	}{
		{"managed, escrowed",
			"profiles: Bootstrap Token supported on server: YES\nprofiles: Bootstrap Token escrowed to server: YES\n", "Enabled"},
		{"escrowed on server wording",
			"profiles: Bootstrap Token supported on server: YES\nprofiles: Bootstrap Token escrowed on server: YES\n", "Enabled"},
		{"lower-case answer",
			"profiles: Bootstrap Token supported on server: yes\nprofiles: Bootstrap Token escrowed to server: yes\n", "Enabled"},
		{"supported but not escrowed",
			"profiles: Bootstrap Token supported on server: YES\nprofiles: Bootstrap Token escrowed to server: NO\n", "Disabled"},
		{"unmanaged Mac",
			"profiles: Bootstrap Token supported on server: NO\nprofiles: Bootstrap Token escrowed to server: NO\n", "Disabled"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("USER", "")
			t.Setenv("LOGNAME", "")
			stubDarwinProcesses(t, map[string]fakeProc{darwinCmdProfiles: {stdout: c.stdout}})
			if got := collectIdentityAccessControl().BootstrapTokenStatus; got != c.want {
				t.Errorf("BootstrapTokenStatus = %q, want %q", got, c.want)
			}
		})
	}
}

// Issue #110 (2): sysadminctl logs its answer through NSLog, i.e. to stderr
// with a timestamp/process prefix, e.g.
// "2024-03-12 09:41:07.512 sysadminctl[812:10422] Secure token is ENABLED for user alice".
// Admin scripts therefore always run it with 2>&1 (the Jamf EA reads field
// $7, which is ENABLED/DISABLED only with that prefix present). Stdout is
// empty.
func TestCollectIdentityAccessControl_SecureTokenOnStderr(t *testing.T) {
	cases := []struct {
		name, stderr, want string
	}{
		{"enabled", "2024-03-12 09:41:07.512 sysadminctl[812:10422] Secure token is ENABLED for user alice\n", "Enabled"},
		{"disabled", "2024-03-12 09:41:07.512 sysadminctl[812:10422] Secure token is DISABLED for user alice\n", "Disabled"},
		{"unexpected", "2024-03-12 09:41:07.512 sysadminctl[812:10422] something else\n", "Unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("USER", "alice")
			stubDarwinProcesses(t, map[string]fakeProc{
				darwinCmdSecToken + "alice": {stderr: c.stderr},
			})
			if got := collectIdentityAccessControl().SecureTokenStatus; got != c.want {
				t.Errorf("SecureTokenStatus = %q, want %q", got, c.want)
			}
		})
	}
}

// Issue #110 (3): `bioutil -r -s` prints numeric flags, never the word
// "enabled". Older macOS labels the lines "Touch ID ...", Sequoia and later
// "Biometrics ..." (Jamf Nation TouchID EA thread; Fleet bioutil guide shows
// "Biometrics for unlock: 1").
func TestCollectIdentityAccessControl_TouchIDRealOutput(t *testing.T) {
	cases := []struct {
		name, stdout, want string
	}{
		{"pre-Sequoia, unlock on",
			"System Touch ID configuration:\n\tTouch ID functionality: 1\n\tTouch ID for unlock: 1\n", "Enabled"},
		{"Sequoia, unlock on",
			"System biometrics configuration:\n\tBiometrics functionality: 1\n\tBiometrics for unlock: 1\n", "Enabled"},
		{"unlock off",
			"System biometrics configuration:\n\tBiometrics functionality: 1\n\tBiometrics for unlock: 0\n", "Disabled"},
		{"functionality off",
			"System Touch ID configuration:\n\tTouch ID functionality: 0\n\tTouch ID for unlock: 1\n", "Disabled"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("USER", "")
			t.Setenv("LOGNAME", "")
			stubDarwinProcesses(t, map[string]fakeProc{darwinCmdBioutil: {stdout: c.stdout}})
			if got := collectIdentityAccessControl().TouchIDStatus; got != c.want {
				t.Errorf("TouchIDStatus = %q, want %q", got, c.want)
			}
		})
	}
}

// Issue #118 (EDR): a product with two known paths must be reported once,
// whether it is detected by both paths or by its running process.
func TestCollectEDRInfo_NoDuplicateProducts(t *testing.T) {
	stubDarwinSecurityCommands(t, map[string]string{
		darwinCmdPs: "COMM\nlaunchd\nosqueryd\nwazuh-agent\n",
	})
	stubDarwinSecurityFS(t, []string{"/var/db/osquery", "/opt/osquery"}, nil)

	var names []string
	for _, a := range collectEDRInfo().Agents {
		names = append(names, a.AgentName)
	}
	want := []string{"Wazuh Agent", "Osquery"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("agents = %q, want %q", names, want)
	}
}

// Issue #118 (T2): SPHardwareDataType never names the T2 chip; the
// iBridge report does ("Model Name: Apple T2 Security Chip", per Jamf Nation
// T2 EA thread; LockRattler matches " T2 " for the same reason, because
// serial numbers and firmware strings can contain "T2").
func TestCollectHardwareSecurity_T2Detection(t *testing.T) {
	const intelNoT2 = "Hardware:\n\n    Hardware Overview:\n\n      Model Name: iMac\n" +
		"      Processor Name: 6-Core Intel Core i5\n      Serial Number (system): C02T2ABCJ1G5\n" +
		"      Hardware UUID: 1A2B3C4D-0000-1111-2222-333344445555\n"
	const intelT2 = "Hardware:\n\n    Hardware Overview:\n\n      Model Name: MacBook Pro\n" +
		"      Processor Name: Quad-Core Intel Core i7\n      Serial Number (system): C02XG0FDJGH5\n"
	const ibridgeT2 = "Controller:\n\n    Controller Information:\n\n      Model Name: Apple T2 Security Chip\n" +
		"      Firmware Version: 20.16.4252.0.0,0\n"
	cases := []struct {
		name      string
		responses map[string]string
		want      string
	}{
		{"serial number contains T2, no T2 chip", map[string]string{darwinCmdHardware: intelNoT2}, "Unsupported"},
		{"T2 named by iBridge report", map[string]string{darwinCmdHardware: intelT2, darwinCmdIBridge: ibridgeT2}, "Enabled"},
		{"iBridge firmware string contains T2 but no T2 chip",
			map[string]string{darwinCmdHardware: intelT2, darwinCmdIBridge: "Controller Information:\n  Firmware Version: 16PT2\n"}, "Unsupported"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stubDarwinSecurityCommands(t, c.responses)
			if got := collectHardwareSecurity().SecureEnclaveStatus; got != c.want {
				t.Errorf("SecureEnclaveStatus = %q, want %q", got, c.want)
			}
		})
	}
}
