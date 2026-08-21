//go:build darwin

package virtualization

import (
	"context"
	"errors"
	"strings"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

// platformCapability reports CapSupported unconditionally: sysctl is part of
// the base macOS system on every supported target.
func platformCapability(context.Context) tel.CapabilityState {
	return tel.CapSupported
}

// platformSignal reads hw.model (fed through classifyVendor — VM software
// such as VMware Fusion and Parallels reports a distinctive model string
// there) and kern.hv_vmm_present, Apple's own "a hypervisor is running this
// guest" flag, as a fallback hint for VMs that spoof a generic Mac model.
func platformSignal(ctx context.Context) (sig signal) {
	var sources []string
	modelFailed, hintFailed := false, false

	if out, err := shared.RunCommandContext(ctx, "sysctl", "-n", "hw.model"); err == nil {
		sig.Model = strings.TrimSpace(out)
		sources = append(sources, "sysctl:hw.model")
	} else {
		sig.Warnings = append(sig.Warnings, "sysctl hw.model failed")
		modelFailed = true
	}

	if out, err := shared.RunCommandContext(ctx, "sysctl", "-n", "kern.hv_vmm_present"); err == nil {
		if strings.TrimSpace(out) == "1" {
			sig.HintVirtual = true
		}
		sources = append(sources, "sysctl:kern.hv_vmm_present")
	} else {
		sig.Warnings = append(sig.Warnings, "sysctl kern.hv_vmm_present failed")
		hintFailed = true
	}

	// Both sysctl calls failing means this cycle produced no classification
	// signal at all — a real error, not a confident bare-metal result. One
	// succeeding is sufficient for classifyVendor/HintVirtual to work with.
	if modelFailed && hintFailed {
		sig.Err = errors.New("macos virtualization detection: both sysctl reads failed")
	}

	sig.Source = strings.Join(sources, ", ")
	return sig
}
