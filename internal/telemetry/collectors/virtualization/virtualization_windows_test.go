//go:build windows

package virtualization

import (
	"context"
	"testing"
)

// TestPlatformSignal_NeverHintsFromAmbiguousSignal is a regression guard for
// the finding recorded in platformSignal's doc comment in
// virtualization_windows.go: Win32_ComputerSystem.HypervisorPresent is true
// whenever ANY hypervisor layer sits under the OS — including the host's own
// Hyper-V role or Virtualization-Based Security/Credential Guard on a
// perfectly physical machine, both common on managed Windows 11 fleets.
//
// platformSignal must classify from Manufacturer/Model alone and never set
// HintVirtual from HypervisorPresent or any other ambiguous OS-level signal.
// This test runs the real platform code (WMI) against whatever host it
// executes on and asserts the invariant holds structurally: it would fail the
// moment someone "helpfully" wires HypervisorPresent back in as a generic
// hint, which is exactly the physical-machine-misclassified-as-virtual
// regression this collector was built to avoid.
func TestPlatformSignal_NeverHintsFromAmbiguousSignal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	sig := platformSignal(context.Background())
	if sig.HintVirtual {
		t.Error("platformSignal set HintVirtual=true on Windows; classification must rely " +
			"solely on Manufacturer/Model (see platformSignal's doc comment) — " +
			"HypervisorPresent must never be reintroduced as a generic hint, or " +
			"physical VBS/Hyper-V-role-enabled machines will be misclassified as virtual")
	}
	if sig.HintHypervisor != "" {
		t.Errorf("platformSignal set HintHypervisor = %q, want empty (Windows has no hint source)", sig.HintHypervisor)
	}
}
