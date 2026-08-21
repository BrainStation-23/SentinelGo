package collectors

import (
	"testing"

	tel "sentinelgo/internal/telemetry"
)

// TestRegisterAllSucceeds catches the one failure mode Register has: a
// duplicate or empty collector name, which is a programming error in this file
// and must surface here rather than at agent startup.
func TestRegisterAllSucceeds(t *testing.T) {
	set := tel.NewCollectorSet()
	if err := RegisterAll(set); err != nil {
		t.Fatalf("RegisterAll() error = %v", err)
	}
	if set.Len() == 0 {
		t.Fatal("RegisterAll() registered nothing")
	}
}

// TestEverySectionIsRegistered guards the gap that left secure_boot and tpm
// reporting a capability default for so long: a section can be declared in the
// registry with a full reconcile policy and still have no collector behind it,
// and nothing in the build complains.
//
// Health is exempt because it is sampled rather than reconciled, and the
// firmware/cpu/memory_modules sections are listed as known-unfilled below so
// that adding a collector for one of them is a deliberate edit here, not a
// silent change in behaviour.
func TestEverySectionIsRegistered(t *testing.T) {
	// Sections declared in the registry that this build knowingly does not
	// collect yet. Every entry is a real gap, recorded rather than hidden.
	knownUnfilled := map[string]string{
		tel.SectionFirmware:      "no firmware/UEFI collector yet",
		tel.SectionCPU:           "CPU detail still served by the legacy inventory pipeline",
		tel.SectionMemoryModules: "no per-DIMM collector yet",
	}

	set := tel.NewCollectorSet()
	if err := RegisterAll(set); err != nil {
		t.Fatalf("RegisterAll() error = %v", err)
	}

	filled := make(map[string]bool, set.Len())
	for _, c := range set.All() {
		filled[c.Section()] = true
	}

	registry := tel.NewDefaultRegistry()
	for _, name := range registry.Names() {
		if filled[name] {
			if reason, listed := knownUnfilled[name]; listed {
				t.Errorf("section %q now has a collector but is still listed as unfilled (%q); remove it from knownUnfilled",
					name, reason)
			}
			continue
		}
		if _, listed := knownUnfilled[name]; !listed {
			t.Errorf("section %q is registered but no collector fills it; either wire one up or record it in knownUnfilled",
				name)
		}
	}
}

// TestPreviouslyUnclaimedKeysNowHaveOwners is the direct regression test for
// the reported bug: secure_boot, tpm and processes.cmdline all reported
// "unavailable_on_os" on a Windows 11 endpoint because no collector claimed
// them, so they kept the capability manifest's default.
//
// It asserts ownership statically — which collector claims which key — rather
// than by running the collectors, so it stays fast and gives the same answer on
// every platform.
func TestPreviouslyUnclaimedKeysNowHaveOwners(t *testing.T) {
	set := tel.NewCollectorSet()
	if err := RegisterAll(set); err != nil {
		t.Fatalf("RegisterAll() error = %v", err)
	}

	// Sections whose collector owns the named capability key.
	wantOwners := map[string]string{
		tel.CapKeySecureBoot: tel.SectionSecureBoot,
		tel.CapKeyTPM:        tel.SectionTPM,
		tel.CapKeyFirewall:   tel.SectionProtection,
	}
	for key, section := range wantOwners {
		if _, ok := set.Get(section); !ok {
			t.Errorf("capability %q has no owner: no collector fills section %q", key, section)
		}
	}

	// Sub-capability keys are claimed through the optional interface, so check
	// that at least one registered collector implements it and claims each.
	wantSubKeys := []string{
		tel.CapKeyProcessesCmdline,
		tel.CapKeyRealtimeProtection,
		tel.CapKeyTamperProtection,
	}
	claimed := make(map[string]bool)
	for _, c := range set.All() {
		reporter, ok := c.(tel.SubCapabilityReporter)
		if !ok {
			continue
		}
		for key := range reporter.SubCapabilities(t.Context(), tel.CollectorConfig{}) {
			claimed[key] = true
		}
	}
	for _, key := range wantSubKeys {
		if !claimed[key] {
			t.Errorf("sub-capability %q is claimed by no collector; it would report the manifest default", key)
		}
	}
}

// TestUnclaimedKeysReportNotCollected documents what the remaining gaps look
// like on the wire. They are real gaps — storage.smart, peripherals.usb and
// network.routing_table have no collector — and the point of the fix is that
// they now say so about the AGENT rather than blaming the operating system.
func TestUnclaimedKeysReportNotCollected(t *testing.T) {
	stillUnclaimed := []string{
		tel.CapKeyStorageSMART,
		tel.CapKeyPeripheralsUSB,
		tel.CapKeyNetworkRoutingTable,
	}

	manifest := tel.NewCapabilityManifest()
	for _, key := range stillUnclaimed {
		got := manifest.Get(key)
		if got != tel.CapNotCollected {
			t.Errorf("%s = %q, want %q", key, got, tel.CapNotCollected)
		}
		if got == tel.CapUnavailableOS {
			t.Errorf("%s blames the operating system for a missing collector", key)
		}
	}
}
