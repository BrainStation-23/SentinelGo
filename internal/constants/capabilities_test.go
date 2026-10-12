package constants

import (
	"regexp"
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
