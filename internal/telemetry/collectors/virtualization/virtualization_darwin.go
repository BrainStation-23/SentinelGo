//go:build darwin

package virtualization

import (
	"context"
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

	if out, err := shared.RunCommandContext(ctx, "sysctl", "-n", "hw.model"); err == nil {
		sig.Model = strings.TrimSpace(out)
		sources = append(sources, "sysctl:hw.model")
	} else {
		sig.Warnings = append(sig.Warnings, "sysctl hw.model failed")
	}

	if out, err := shared.RunCommandContext(ctx, "sysctl", "-n", "kern.hv_vmm_present"); err == nil {
		if strings.TrimSpace(out) == "1" {
			sig.HintVirtual = true
		}
		sources = append(sources, "sysctl:kern.hv_vmm_present")
	} else {
		sig.Warnings = append(sig.Warnings, "sysctl kern.hv_vmm_present failed")
	}

	sig.Source = strings.Join(sources, ", ")
	return sig
}
