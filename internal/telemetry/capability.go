package telemetry

import "sort"

// CapabilityState explains why a telemetry capability does or does not produce
// data on this endpoint.
//
// The distinction matters operationally: without it, "this desktop has no
// battery", "this laptop's battery exists but the firmware exposes nothing",
// "an admin turned the collector off" and "collection crashed" all arrive at
// the backend as the same empty field, and an operator cannot tell which of
// them needs action.
type CapabilityState string

const (
	// CapSupported: the feature is present and was collected successfully.
	CapSupported CapabilityState = "supported"

	// CapNotPresent: the hardware or feature is genuinely absent from this
	// device — no TPM chip, no battery in a desktop. Nothing is wrong and no
	// action is possible.
	CapNotPresent CapabilityState = "not_present"

	// CapUnsupported: the feature exists on this device, but this host's
	// driver, firmware or configuration will not expose it — a battery whose
	// SMBIOS class returns nothing, a RAID controller that hides SMART. Unlike
	// CapNotPresent this may be fixable by a driver or firmware change.
	CapUnsupported CapabilityState = "unsupported"

	// CapDisabled: collection was switched off by configuration.
	CapDisabled CapabilityState = "disabled"

	// CapUnavailableOS: this operating system cannot provide the data at all.
	// Reserved for a real platform limitation established by a collector that
	// actually looked — never for "nobody reported anything", which is
	// CapNotCollected.
	CapUnavailableOS CapabilityState = "unavailable_on_os"

	// CapNotCollected: this build ships no collector that claims the key, so
	// the agent has not determined anything about it either way.
	//
	// This exists because the honest answer to "why is secure_boot absent on a
	// Windows 11 endpoint that plainly has it" is "the agent never asked", and
	// the previous default said "this OS cannot provide it" — a claim about the
	// platform that nothing had verified. An operator reading unavailable_on_os
	// stops investigating; not_collected tells them the gap is on the agent
	// side and is fixable by shipping a collector.
	CapNotCollected CapabilityState = "not_collected"
)

// Valid reports whether s is a recognised capability state.
func (s CapabilityState) Valid() bool {
	switch s {
	case CapSupported, CapNotPresent, CapUnsupported, CapDisabled,
		CapUnavailableOS, CapNotCollected:
		return true
	default:
		return false
	}
}

func (s CapabilityState) String() string { return string(s) }

// Capability keys. These are part of the backend contract: add to this list,
// never rename an existing entry.
const (
	CapKeyStorageSMART        = "storage.smart"
	CapKeyStorageEncryption   = "storage.encryption"
	CapKeyPatchInventory      = "patch_inventory"
	CapKeySessions            = "sessions"
	CapKeyProcesses           = "processes"
	CapKeyProcessesCmdline    = "processes.cmdline"
	CapKeyBatteryDetail       = "battery_detail"
	CapKeyTPM                 = "tpm"
	CapKeySecureBoot          = "secure_boot"
	CapKeyCertificates        = "certificates"
	CapKeyDirectoryJoin       = "directory_join"
	CapKeyNetworkRoutingTable = "network.routing_table"
	CapKeyPersistence         = "persistence"
	CapKeyPeripheralsUSB      = "peripherals.usb"
	// Endpoint-protection controls. Split into three keys rather than one
	// "security" key because they fail independently: a host can have a
	// readable firewall state and an unreadable tamper-protection state, and
	// collapsing them would report the weaker of the two for both.
	CapKeyFirewall           = "security.firewall"
	CapKeyRealtimeProtection = "security.realtime_protection"
	CapKeyTamperProtection   = "security.tamper_protection"
	// CapKeyVirtualization covers VM/hypervisor detection. Unlike most keys
	// this is rarely CapNotPresent (bare metal is a legitimate "supported,
	// is_virtual=false" result) — it exists for the genuine failure mode where
	// this host offers no detection mechanism at all, e.g. a minimal Linux
	// image with neither systemd-detect-virt nor a readable DMI table.
	CapKeyVirtualization = "virtualization"
)

// AllCapabilityKeys lists every capability the agent knows about, so a manifest
// can report an explicit state for each rather than omitting unknown ones.
func AllCapabilityKeys() []string {
	return []string{
		CapKeyStorageSMART,
		CapKeyStorageEncryption,
		CapKeyPatchInventory,
		CapKeySessions,
		CapKeyProcesses,
		CapKeyProcessesCmdline,
		CapKeyBatteryDetail,
		CapKeyTPM,
		CapKeySecureBoot,
		CapKeyCertificates,
		CapKeyDirectoryJoin,
		CapKeyNetworkRoutingTable,
		CapKeyPersistence,
		CapKeyPeripheralsUSB,
		CapKeyVirtualization,
		CapKeyFirewall,
		CapKeyRealtimeProtection,
		CapKeyTamperProtection,
	}
}

// CapabilityManifest maps a capability key to its state on this endpoint.
type CapabilityManifest map[string]CapabilityState

// NewCapabilityManifest returns a manifest with every known capability marked
// not_collected. Collectors overwrite the keys they own during collection, so a
// capability nobody claimed reports a defined state instead of vanishing.
//
// The default is deliberately not unavailable_on_os: that is an assertion about
// the operating system, and the only thing an unclaimed key actually proves is
// that no collector in this build asked. See CapNotCollected.
func NewCapabilityManifest() CapabilityManifest {
	m := make(CapabilityManifest, len(AllCapabilityKeys()))
	for _, k := range AllCapabilityKeys() {
		m[k] = CapNotCollected
	}
	return m
}

// Set records state for key. Invalid states are coerced to CapNotCollected so
// a collector bug cannot put an unrecognised value on the wire — and cannot
// launder itself into a claim about the operating system either.
func (m CapabilityManifest) Set(key string, state CapabilityState) {
	if !state.Valid() {
		state = CapNotCollected
	}
	m[key] = state
}

// Get returns the state for key, or CapNotCollected when it is not recorded.
func (m CapabilityManifest) Get(key string) CapabilityState {
	if s, ok := m[key]; ok {
		return s
	}
	return CapNotCollected
}

// Keys returns the manifest's capability keys in sorted order, for stable
// output in CLI listings and tests.
func (m CapabilityManifest) Keys() []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Clone returns an independent copy, so a manifest handed to an uploader cannot
// be mutated by a later collection cycle.
func (m CapabilityManifest) Clone() CapabilityManifest {
	out := make(CapabilityManifest, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
