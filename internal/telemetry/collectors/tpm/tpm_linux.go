//go:build linux

package tpm

import (
	"context"
	"os"
	"strings"

	tel "sentinelgo/internal/telemetry"
)

const (
	tpmSysfsDir   = "/sys/class/tpm/tpm0"
	tpmClassDir   = "/sys/class/tpm"
	tpmDeviceNode = "/dev/tpm0"
	linuxSource   = "sysfs:/sys/class/tpm"
)

// platformProbe reads sysfs only — no subprocess, no cost worth caching for its
// own sake, but it shares the probe path so the collector stays uniform.
//
// The three cases are genuinely different and are kept apart: a device node
// under /dev means a usable TPM; a /sys/class/tpm directory with no device node
// means the kernel driver is loaded but the chip is disabled in firmware; and
// no /sys/class/tpm at all means there is nothing to report.
func platformProbe(context.Context) probe {
	_, sysfsErr := os.Stat(tpmSysfsDir)
	_, devErr := os.Stat(tpmDeviceNode)

	if sysfsErr != nil && devErr != nil {
		if _, err := os.Stat(tpmClassDir); err != nil {
			return probe{
				capability: tel.CapNotPresent,
				signal:     signal{Payload: Payload{Present: false}, Source: linuxSource},
			}
		}
		// The TPM class exists but holds no device: the subsystem is compiled
		// in and found nothing.
		return probe{
			capability: tel.CapNotPresent,
			signal:     signal{Payload: Payload{Present: false}, Source: linuxSource},
		}
	}

	enabled := devErr == nil
	payload := Payload{
		Present: true,
		Enabled: &enabled,
		Version: readTPMVersion(),
	}
	if id := readTrimmed(tpmSysfsDir + "/device/description"); id != "" {
		payload.Manufacturer = id
	}

	return probe{
		capability: tel.CapSupported,
		signal:     signal{Payload: payload, Source: linuxSource},
	}
}

// readTPMVersion prefers the explicit major-version file and falls back to the
// device description, which spells out "TPM 2.0" on most drivers.
func readTPMVersion() string {
	if v := linuxVersion(readTrimmed(tpmSysfsDir + "/tpm_version_major")); v != "" {
		return v
	}
	desc := readTrimmed(tpmSysfsDir + "/device/description")
	switch {
	case strings.Contains(desc, "2.0"):
		return "2.0"
	case strings.Contains(desc, "1.2"):
		return "1.2"
	default:
		return ""
	}
}

func readTrimmed(path string) string {
	data, err := os.ReadFile(path) // #nosec G304 - fixed sysfs paths
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
