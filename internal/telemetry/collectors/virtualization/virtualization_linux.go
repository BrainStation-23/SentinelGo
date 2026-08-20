//go:build linux

package virtualization

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

// platformCapability reports whether this host offers any detection
// mechanism at all. Most Linux images have both systemd-detect-virt and a
// readable DMI table; the genuine unsupported case is a minimal image with
// neither — a stripped container base or an ARM board without DMI tables.
func platformCapability(context.Context) tel.CapabilityState {
	if _, err := exec.LookPath("systemd-detect-virt"); err == nil {
		return tel.CapSupported
	}
	if _, err := os.Stat("/sys/class/dmi/id"); err == nil {
		return tel.CapSupported
	}
	return tel.CapUnsupported
}

// platformSignal combines two sources: DMI vendor/product strings (fed
// through the same classifyVendor used on every platform, so it can name a
// cloud provider) and systemd-detect-virt (which reliably names the
// hypervisor but cannot distinguish a cloud provider from an on-prem host
// running the same hypervisor).
func platformSignal(ctx context.Context) (sig signal) {
	var sources []string

	if v, err := shared.ReadFileContent("/sys/class/dmi/id/sys_vendor"); err == nil {
		sig.Manufacturer = strings.TrimSpace(v)
		sources = append(sources, "sysfs:/sys/class/dmi/id/sys_vendor")
	}
	if v, err := shared.ReadFileContent("/sys/class/dmi/id/product_name"); err == nil {
		sig.Model = strings.TrimSpace(v)
		sources = append(sources, "sysfs:/sys/class/dmi/id/product_name")
	}
	if sig.Manufacturer == "" && sig.Model == "" {
		sig.Warnings = append(sig.Warnings, "DMI vendor/product strings unreadable")
	}

	if _, err := exec.LookPath("systemd-detect-virt"); err != nil {
		sig.Warnings = append(sig.Warnings, "systemd-detect-virt not installed")
	} else {
		out, _, err := shared.RunCommandOutputContext(ctx, "systemd-detect-virt", "--vm")
		if err != nil {
			sig.Warnings = append(sig.Warnings, "systemd-detect-virt failed to run")
		} else {
			if hv, isVirt := mapSystemdVirt(out); isVirt {
				sig.HintVirtual = true
				sig.HintHypervisor = hv
			}
			sources = append(sources, "exec:systemd-detect-virt")
		}
	}

	// ", " rather than "+": the sysfs paths here are long enough, and drawn
	// entirely from the token/key character class, that a "+"-joined run can
	// exceed 32 characters and trip SanitizeMessage's secret-shaped-token
	// redaction — turning this harmless diagnostic string into "<redacted>"
	// in every log and CollectorResult.
	sig.Source = strings.Join(sources, ", ")
	return sig
}
