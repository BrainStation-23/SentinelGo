//go:build linux

package secureboot

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

const efivarsDir = "/sys/firmware/efi/efivars"

// platformCapability stats /sys/firmware/efi. Its absence means the kernel
// booted without UEFI, so there is no Secure Boot state to read — a genuine
// firmware answer, not a failure. This costs a single stat.
func platformCapability(context.Context) tel.CapabilityState {
	if _, err := os.Stat("/sys/firmware/efi"); err != nil {
		return tel.CapNotPresent
	}
	return tel.CapSupported
}

// platformSecureBoot prefers mokutil (it reports the state directly) and falls
// back to reading the raw EFI variable, which needs no extra package installed.
func platformSecureBoot(ctx context.Context) signal {
	if out, err := shared.RunCommandContext(ctx, "mokutil", "--sb-state"); err == nil {
		if state := parseMokutil(out); state != StateUnknown {
			return signal{State: state, Mechanism: "exec:mokutil", Source: "exec:mokutil"}
		}
	}

	state, err := secureBootFromEFIVars(efivarsDir)
	if err != nil {
		return signal{
			State:    StateUnknown,
			Source:   "efivars:" + efivarsDir,
			Warnings: []string{"SecureBoot EFI variable is not readable"},
		}
	}
	return signal{State: state, Mechanism: "efivars:SecureBoot", Source: "efivars:" + efivarsDir}
}

// secureBootFromEFIVars locates the SecureBoot-<guid> variable and decodes it.
func secureBootFromEFIVars(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return StateUnknown, err
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "SecureBoot-") {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(dir, e.Name()))
		if readErr != nil {
			return StateUnknown, readErr
		}
		return parseEFIVar(data), nil
	}
	return StateUnknown, os.ErrNotExist
}
