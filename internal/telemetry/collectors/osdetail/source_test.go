package osdetail

import (
	"strings"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

// TestSourceStringsSurviveSanitization is a regression test — see the
// identical test in the virtualization package for the full explanation of
// why a harmless "+"-joined diagnostic string can accidentally match
// SanitizeMessage's secret-shaped-token redaction. osdetail_linux.go's
// "best-effort:install-date+reboot-required-check" was the string that
// originally surfaced this bug class.
func TestSourceStringsSurviveSanitization(t *testing.T) {
	worstCase := []string{
		strings.Join([]string{"registry:InstallDate", "registry:reboot-pending", "wmi:SoftwareLicensingProduct"}, ", "), // windows
		strings.Join([]string{"best-effort:install-date", "reboot-required-check"}, ", "),                               // linux
		strings.Join([]string{"stat:/var/db/.AppleSetupDone"}, ", "),                                                    // darwin
	}
	for _, s := range worstCase {
		if got := tel.SanitizeMessage(s); got != s {
			t.Errorf("SanitizeMessage altered a Source string with nothing sensitive in it:\n  in:  %q\n  out: %q", s, got)
		}
	}
}
