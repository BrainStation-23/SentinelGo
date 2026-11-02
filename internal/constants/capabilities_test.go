package constants

import (
	"regexp"
	"slices"
	"testing"
)

func TestAgentCapabilities_Valid(t *testing.T) {
	re := regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	seen := map[string]bool{}
	for _, c := range AgentCapabilities {
		if !re.MatchString(c) {
			t.Errorf("capability %q does not match %s", c, re)
		}
		if seen[c] {
			t.Errorf("capability %q listed twice", c)
		}
		seen[c] = true
	}
}

func TestCapabilities_ReturnsCopy(t *testing.T) {
	got := Capabilities()
	got[0] = "changed"
	if AgentCapabilities[0] == "changed" {
		t.Error("Capabilities() returned the shared slice")
	}
}

func TestCapabilityScriptPwsh_Valid(t *testing.T) {
	re := regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	if !re.MatchString(CapabilityScriptPwsh) {
		t.Errorf("capability %q does not match %s", CapabilityScriptPwsh, re)
	}
	for _, c := range AgentCapabilities {
		if c == CapabilityScriptPwsh {
			t.Errorf("%q must not be in the static list: it depends on the device", c)
		}
	}
}

func TestCapabilities_PwshDependsOnDevice(t *testing.T) {
	orig := pwshInstalled
	t.Cleanup(func() { pwshInstalled = orig })

	for _, installed := range []bool{true, false} {
		pwshInstalled = func() bool { return installed }
		got := Capabilities()
		if has := slices.Contains(got, CapabilityScriptPwsh); has != installed {
			t.Errorf("pwsh installed=%v: Capabilities() = %q, contains %s = %v", installed, got, CapabilityScriptPwsh, has)
		}
		if !slices.Equal(got[:len(AgentCapabilities)], AgentCapabilities) {
			t.Errorf("Capabilities() = %q, want the static list first", got)
		}
	}
}

// apple_mdm_state_v1 is advertised on macOS only (#349).
func TestCapabilities_AppleMDMStateOnMacOnly(t *testing.T) {
	prev := goos
	t.Cleanup(func() { goos = prev })
	for os, want := range map[string]bool{"darwin": true, "linux": false, "windows": false} {
		goos = os
		if got := slices.Contains(Capabilities(), CapabilityAppleMDMState); got != want {
			t.Errorf("%s: apple_mdm_state_v1 advertised = %v, want %v", os, got, want)
		}
	}
	if slices.Contains(AgentCapabilities, CapabilityAppleMDMState) {
		t.Error("apple_mdm_state_v1 must not be in the static list")
	}
}

// windows_mdm_state_v1 is advertised on Windows only (#355).
func TestCapabilities_WindowsMDMStateOnWindowsOnly(t *testing.T) {
	prev := goos
	t.Cleanup(func() { goos = prev })
	for os, want := range map[string]bool{"windows": true, "darwin": false, "linux": false} {
		goos = os
		if got := slices.Contains(Capabilities(), CapabilityWindowsMDMState); got != want {
			t.Errorf("%s: windows_mdm_state_v1 advertised = %v, want %v", os, got, want)
		}
		if got := slices.Contains(Capabilities(), CapabilityMDMSync); got != want {
			t.Errorf("%s: mdm_sync_v1 advertised = %v, want %v", os, got, want)
		}
	}
}
