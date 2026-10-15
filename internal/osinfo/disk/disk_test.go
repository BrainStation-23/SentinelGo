package disk

import (
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

func TestManufacturerFromModel(t *testing.T) {
	cases := []struct {
		model string
		want  string
	}{
		{"Samsung SSD 870 EVO 500GB", "Samsung"},
		{"SAMSUNG MZNLN256HAJQ", "Samsung"},
		{"WDC WD10EZEX-08WN4A0", "Western Digital"},
		{"WD Blue SN570", "Western Digital"},
		// Seagate drives that include the name explicitly
		{"Seagate ST2000DM008", "Seagate"},
		{"TOSHIBA MQ04ABF100", "Toshiba"},
		{"APPLE SSD AP1024Q", "Apple"},
		{"Intel SSDPEKNW512G8", "Intel"},
		// Crucial drives that include the name explicitly
		{"Crucial CT500MX500SSD1", "Crucial"},
		{"KINGSTON SA400S37240G", "Kingston"},
		{"SanDisk SSD PLUS 480GB", "SanDisk"},
		// SK Hynix drives where name is present
		{"SK Hynix PC711 512GB", "SK Hynix"},
		// Model-number-only strings not containing manufacturer name fall back to the model
		{"ST2000DM008-2FR102", "ST2000DM008-2FR102"},
		{"HFM512GD3JX013N", "HFM512GD3JX013N"},
		{"UnknownBrand XYZ", "UnknownBrand XYZ"},
		{"", ""},
	}
	for _, c := range cases {
		got := manufacturerFromModel(c.model)
		if got != c.want {
			t.Errorf("manufacturerFromModel(%q) = %q, want %q", c.model, got, c.want)
		}
	}
}

// validEncState reports whether s is one of the encryption_state values the
// server's check constraint accepts.
func validEncState(s string) bool {
	switch s {
	case encStateFull, encStatePartial, encStateNone, encStateEncrypting, encStateDecrypting, encStateUnknown:
		return true
	}
	return false
}

// checkPartitionInvariants fails t if p breaks a rule the server relies on.
func checkPartitionInvariants(t *testing.T, p shared.DiskPartition) {
	t.Helper()
	if !validEncState(p.EncryptionState) {
		t.Fatalf("encryption_state = %q, not in the allowed set", p.EncryptionState)
	}
	if p.PartitionNumber < 0 {
		t.Fatalf("partition_number = %d, want >= 0", p.PartitionNumber)
	}
	if pct := p.EncryptionPercentage; pct != nil && (*pct < 0 || *pct > 100) {
		t.Fatalf("encryption_percentage = %v, want 0..100", *pct)
	}
}

func TestSummarizeDiskEncryption(t *testing.T) {
	part := func(typ, state string, boot, system bool) shared.DiskPartition {
		return shared.DiskPartition{PartitionType: typ, EncryptionState: state, IsBoot: boot, IsSystem: system}
	}
	efi := part("EFI", encStateNone, false, true)
	msr := part("MSR", encStateNone, false, false)
	recovery := part("Recovery", encStateNone, false, false)
	cases := []struct {
		name  string
		parts []shared.DiskPartition
		want  string
	}{
		{"no partitions", nil, "unknown"},
		{"standard install, C: encrypted", []shared.DiskPartition{efi, msr, part("Basic", encStateFull, true, false), recovery}, "enabled"},
		{"standard install, C: not encrypted", []shared.DiskPartition{efi, msr, part("Basic", encStateNone, true, false), recovery}, "disabled"},
		{"C: encrypting", []shared.DiskPartition{efi, part("Basic", encStateEncrypting, true, false)}, "enabled"},
		{"C: paused", []shared.DiskPartition{part("Basic", encStatePartial, true, false)}, "enabled"},
		{"C: decrypting", []shared.DiskPartition{part("Basic", encStateDecrypting, true, false)}, "disabled"},
		{"boot volume decides over data volume", []shared.DiskPartition{part("Basic", encStateFull, false, false), part("Basic", encStateNone, true, false)}, "disabled"},
		{"boot volume unknown", []shared.DiskPartition{part("Basic", encStateUnknown, true, false), part("Basic", encStateFull, false, false)}, "unknown"},
		{"data disk, one volume encrypted", []shared.DiskPartition{part("Basic", encStateNone, false, false), part("Basic", encStateFull, false, false)}, "enabled"},
		{"data disk, unknown and none", []shared.DiskPartition{part("Basic", encStateUnknown, false, false), part("Basic", encStateNone, false, false)}, "disabled"},
		{"only reserved partitions", []shared.DiskPartition{efi, msr, recovery}, "unknown"},
		{"Windows Home", []shared.DiskPartition{part("EFI", encStateUnknown, false, true), part("Basic", encStateUnknown, true, false)}, "unknown"},
		{"Linux EFI by type name", []shared.DiskPartition{part("EFI System", encStateNone, false, false), part("Linux filesystem", encStateFull, false, false)}, "enabled"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, decider := summarizeDiskEncryption(c.parts)
			if got != c.want {
				t.Errorf("status = %q, want %q", got, c.want)
			}
			if (decider == nil) != (got == "unknown" && !hasBoot(c.parts)) {
				t.Errorf("decider = %v for status %q", decider, got)
			}
		})
	}
}

func hasBoot(parts []shared.DiskPartition) bool {
	for _, p := range parts {
		if p.IsBoot {
			return true
		}
	}
	return false
}

// logPartitions checks and logs disk i's partitions in the integration tests.
func logPartitions(t *testing.T, i int, d shared.DiskDevice) {
	t.Helper()
	if d.Partitions == nil {
		t.Errorf("disks[%d].Partitions is nil, want an array", i)
	}
	for _, p := range d.Partitions {
		checkPartitionInvariants(t, p)
		t.Logf("  partition %d: type=%s letter=%s mount=%s fs=%s size=%d enc=%s",
			p.PartitionNumber, p.PartitionType, p.DriveLetter, p.MountPoint, p.FileSystem, p.SizeBytes, p.EncryptionState)
	}
}
