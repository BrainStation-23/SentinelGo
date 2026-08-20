package virtualization

import (
	"strings"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

// TestSourceStringsSurviveSanitization is a regression test: a CollectorResult
// carries its Source field through tel.SanitizeMessage before reaching any
// log line or the wire, and that function redacts anything that LOOKS like a
// secret — including any unbroken run of 32+ characters drawn from
// [A-Za-z0-9+/_-]. A "+"-joined list of hyphenated mechanism names (sysfs
// paths, PowerShell cmdlet names) can accidentally satisfy that pattern with
// nothing sensitive in it at all, silently turning a useful diagnostic string
// into "<redacted>" in every log and CollectorResult. This reconstructs the
// worst-case (every source present) string each platform file can produce —
// exercised here rather than only on its native OS, since the string
// construction itself has no build tag dependency worth testing — and checks
// it survives sanitization unchanged.
func TestSourceStringsSurviveSanitization(t *testing.T) {
	worstCase := []string{
		strings.Join([]string{"sysctl:hw.model", "sysctl:kern.hv_vmm_present"}, ", "),                                                          // darwin
		strings.Join([]string{"sysfs:/sys/class/dmi/id/sys_vendor", "sysfs:/sys/class/dmi/id/product_name", "exec:systemd-detect-virt"}, ", "), // linux
		"wmi:root/cimv2:Win32_ComputerSystem", // windows
	}
	for _, s := range worstCase {
		if got := tel.SanitizeMessage(s); got != s {
			t.Errorf("SanitizeMessage altered a Source string with nothing sensitive in it:\n  in:  %q\n  out: %q", s, got)
		}
	}
}
