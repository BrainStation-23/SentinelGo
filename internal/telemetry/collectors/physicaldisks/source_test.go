package physicaldisks

import (
	"testing"

	tel "sentinelgo/internal/telemetry"
)

// TestSourceStringsSurviveSanitization is a regression test — see the
// identical test in the virtualization package for the full explanation of
// why a harmless "+"-joined diagnostic string can accidentally match
// SanitizeMessage's secret-shaped-token redaction.
// physicaldisks_windows.go's original
// "Get-PhysicalDisk+Get-StorageReliabilityCounter" was one of the two
// strings that originally surfaced this bug class.
func TestSourceStringsSurviveSanitization(t *testing.T) {
	worstCase := []string{
		"powershell:Get-PhysicalDisk, Get-StorageReliabilityCounter", // windows
		"exec:lsblk, exec:smartctl",                                  // linux
		"exec:diskutil",                                              // darwin
	}
	for _, s := range worstCase {
		if got := tel.SanitizeMessage(s); got != s {
			t.Errorf("SanitizeMessage altered a Source string with nothing sensitive in it:\n  in:  %q\n  out: %q", s, got)
		}
	}
}
