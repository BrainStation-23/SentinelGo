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
