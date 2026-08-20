package identity

import (
	"strings"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

// TestSourceStringsSurviveSanitization is a regression test — see the
// identical test in the virtualization package for the full explanation of
// why a harmless "+"-joined diagnostic string can accidentally match
// SanitizeMessage's secret-shaped-token redaction. This package already
// joins with "," rather than "+"; this test guards against that changing
// back under a future edit.
func TestSourceStringsSurviveSanitization(t *testing.T) {
	worstCase := "wmi:root/cimv2:" + strings.Join([]string{
		"Win32_ComputerSystem", "Win32_ComputerSystemProduct",
		"Win32_SystemEnclosure", "Win32_BaseBoard", "registry:MachineGuid",
	}, ",")
	if got := tel.SanitizeMessage(worstCase); got != worstCase {
		t.Errorf("SanitizeMessage altered a Source string with nothing sensitive in it:\n  in:  %q\n  out: %q", worstCase, got)
	}
}
