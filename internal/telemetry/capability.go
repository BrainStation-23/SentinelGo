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
	CapUnavailableOS CapabilityState = "unavailable_on_os"
)

// Valid reports whether s is a recognised capability state.
func (s CapabilityState) Valid() bool {
	switch s {
	case CapSupported, CapNotPresent, CapUnsupported, CapDisabled, CapUnavailableOS:
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
	}
}

// CapabilityManifest maps a capability key to its state on this endpoint.
type CapabilityManifest map[string]CapabilityState

// NewCapabilityManifest returns a manifest with every known capability marked
// unavailable_on_os. Collectors overwrite the keys they own during collection,
// so a capability nobody claimed reports a defined state instead of vanishing.
func NewCapabilityManifest() CapabilityManifest {
	m := make(CapabilityManifest, len(AllCapabilityKeys()))
	for _, k := range AllCapabilityKeys() {
		m[k] = CapUnavailableOS
	}
	return m
}

// Set records state for key. Invalid states are coerced to CapUnavailableOS so
// a collector bug cannot put an unrecognised value on the wire.
func (m CapabilityManifest) Set(key string, state CapabilityState) {
	if !state.Valid() {
		state = CapUnavailableOS
	}
	m[key] = state
}

// Get returns the state for key, or CapUnavailableOS when it is not recorded.
func (m CapabilityManifest) Get(key string) CapabilityState {
	if s, ok := m[key]; ok {
		return s
	}
	return CapUnavailableOS
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
