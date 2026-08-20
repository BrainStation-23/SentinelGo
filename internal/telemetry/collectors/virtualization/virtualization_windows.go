//go:build windows

package virtualization

import (
	"context"

	"github.com/yusufpapurcu/wmi"

	tel "sentinelgo/internal/telemetry"
)

type win32ComputerSystem struct {
	Manufacturer string
	Model        string
}

// platformCapability reports CapSupported unconditionally: WMI's
// Win32_ComputerSystem class is present on every supported Windows target.
func platformCapability(context.Context) tel.CapabilityState {
	return tel.CapSupported
}

// platformSignal queries Win32_ComputerSystem for Manufacturer and Model,
// which classifyVendor turns into a hypervisor/cloud verdict.
//
// Deliberately NOT queried: Win32_ComputerSystem.HypervisorPresent. It is true
// whenever any hypervisor layer sits under the OS — including the host's own
// Hyper-V role or Virtualization-Based Security/Credential Guard on a
// perfectly physical machine, both common on managed Windows 11 fleets. Using
// it as a generic "is this a VM" signal would misclassify those physical
// laptops as virtual, which is worse than the false negative of leaving an
// unrecognised VM's hypervisor field empty. Manufacturer/Model classification
// is the only signal used here.
func platformSignal(_ context.Context) (sig signal) {
	defer func() {
		if r := recover(); r != nil {
			sig.Warnings = append(sig.Warnings, "wmi query panicked")
		}
	}()

	var cs []win32ComputerSystem
	if err := wmi.Query("SELECT Manufacturer, Model FROM Win32_ComputerSystem", &cs); err != nil {
		sig.Warnings = append(sig.Warnings, "Win32_ComputerSystem query failed")
		return sig
	}
	if len(cs) == 0 {
		sig.Warnings = append(sig.Warnings, "Win32_ComputerSystem returned no rows")
		return sig
	}

	sig.Manufacturer = cs[0].Manufacturer
	sig.Model = cs[0].Model
	sig.Source = "wmi:root/cimv2:Win32_ComputerSystem"
	return sig
}
