package disk

import (
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// Get returns physical disk devices for the current platform.
func Get() []shared.DiskDevice {
	return getDisks()
}

var knownManufacturers = []struct {
	prefix string
	name   string
}{
	{"samsung", "Samsung"},
	{"western digital", "Western Digital"},
	{"wd", "Western Digital"},
	{"seagate", "Seagate"},
	{"toshiba", "Toshiba"},
	{"hitachi", "Hitachi"},
	{"hgst", "HGST"},
	{"apple", "Apple"},
	{"intel", "Intel"},
	{"micron", "Micron"},
	{"crucial", "Crucial"},
	{"sk hynix", "SK Hynix"},
	{"hynix", "SK Hynix"},
	{"kingston", "Kingston"},
	{"sandisk", "SanDisk"},
	{"corsair", "Corsair"},
	{"adata", "ADATA"},
	{"transcend", "Transcend"},
	{"sabrent", "Sabrent"},
	{"kingspec", "KingSpec"},
}

func manufacturerFromModel(model string) string {
	lower := strings.ToLower(model)
	for _, m := range knownManufacturers {
		if strings.HasPrefix(lower, m.prefix) || strings.Contains(lower, " "+m.prefix) {
			return m.name
		}
	}
	return model
}

// Partition encryption states. They match the encryption_state check
// constraint on sentinel-ops' agent_disk_partitions table, so the server can
// store them as-is.
const (
	encStateFull       = "full"
	encStatePartial    = "partial"
	encStateNone       = "none"
	encStateEncrypting = "encrypting"
	encStateDecrypting = "decrypting"
	encStateUnknown    = "unknown"
)

// isReservedPartition reports whether p is a firmware, boot-loader or
// recovery partition (EFI, MSR, BIOS boot, WinRE). These are unencrypted on
// every correctly configured machine, so they don't decide whether a disk
// counts as encrypted.
func isReservedPartition(p shared.DiskPartition) bool {
	if p.IsSystem {
		return true
	}
	t := strings.ToLower(p.PartitionType)
	for _, s := range []string{"efi", "msr", "microsoft reserved", "recovery", "bios boot"} {
		if strings.Contains(t, s) {
			return true
		}
	}
	return false
}

// diskStatusForState maps a partition encryption state to the disk-level
// encryption_status vocabulary (enabled | disabled | unknown). A paused
// conversion still counts as enabled: encryption was turned on and part of
// the volume is already encrypted. Decryption counts as disabled because
// encryption has been turned off.
func diskStatusForState(state string) string {
	switch state {
	case encStateFull, encStateEncrypting, encStatePartial:
		return "enabled"
	case encStateNone, encStateDecrypting:
		return "disabled"
	default:
		return "unknown"
	}
}

// summarizeDiskEncryption derives a disk's encryption_status from its
// partitions, and returns the partition that decided it (nil when none did).
// The partition holding the running OS decides when it's on this disk.
// Otherwise any encrypted data partition makes the disk enabled, and it is
// disabled only when every data partition with a known state is unencrypted.
// Reserved partitions (EFI, MSR, Recovery) are ignored.
func summarizeDiskEncryption(parts []shared.DiskPartition) (string, *shared.DiskPartition) {
	for i := range parts {
		if parts[i].IsBoot && !isReservedPartition(parts[i]) {
			return diskStatusForState(parts[i].EncryptionState), &parts[i]
		}
	}
	var disabled *shared.DiskPartition
	for i := range parts {
		p := &parts[i]
		if isReservedPartition(*p) {
			continue
		}
		switch diskStatusForState(p.EncryptionState) {
		case "enabled":
			return "enabled", p
		case "disabled":
			if disabled == nil {
				disabled = p
			}
		}
	}
	if disabled != nil {
		return "disabled", disabled
	}
	return "unknown", nil
}
