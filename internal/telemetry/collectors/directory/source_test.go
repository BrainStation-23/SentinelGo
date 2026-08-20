package directory

import (
	"strings"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

// TestSourceStringsSurviveSanitization is a regression test — see the
// identical test in the virtualization package for the full explanation of
// why a harmless "+"-joined diagnostic string can accidentally match
// SanitizeMessage's secret-shaped-token redaction.
func TestSourceStringsSurviveSanitization(t *testing.T) {
	worstCase := []string{
		strings.Join([]string{"wmi:Win32_ComputerSystem", "exec:dsregcmd"}, ", "), // windows
		"exec:realm",               // linux
		"file:/etc/sssd/sssd.conf", // linux fallback
		"exec:dsconfigad",          // darwin
	}
	for _, s := range worstCase {
		if got := tel.SanitizeMessage(s); got != s {
			t.Errorf("SanitizeMessage altered a Source string with nothing sensitive in it:\n  in:  %q\n  out: %q", s, got)
		}
	}
}
