package encryption

import "testing"

func TestParseWindowsVolumes_Array(t *testing.T) {
	const sample = `[{"MountPoint":"C:","ProtectionStatus":"On","EncryptionPercentage":100,"KeyProtectorTypes":["Tpm","RecoveryPassword"]}]`
	rows, err := parseWindowsVolumes(sample)
	if err != nil {
		t.Fatalf("parseWindowsVolumes: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	v := rows[0].toVolume()
	if v.DriveLetter != "C:" || v.ProtectionStatus != "on" || v.EncryptionType != "bitlocker" {
		t.Errorf("volume = %+v", v)
	}
	if v.EncryptionPercentage == nil || *v.EncryptionPercentage != 100 {
		t.Errorf("percentage = %v", v.EncryptionPercentage)
	}
	if len(v.KeyProtectorTypes) != 2 {
		t.Errorf("key protectors = %v", v.KeyProtectorTypes)
	}
}

func TestParseWindowsVolumes_Off(t *testing.T) {
	const sample = `{"MountPoint":"D:","ProtectionStatus":"Off","EncryptionPercentage":0,"KeyProtectorTypes":[]}`
	rows, err := parseWindowsVolumes(sample)
	if err != nil {
		t.Fatalf("parseWindowsVolumes: %v", err)
	}
	v := rows[0].toVolume()
	if v.ProtectionStatus != "off" || v.EncryptionType != "none" {
		t.Errorf("volume = %+v", v)
	}
}

func TestParseWindowsVolumes_Empty(t *testing.T) {
	rows, err := parseWindowsVolumes("")
	if err != nil || rows != nil {
		t.Errorf("got (%v, %v), want (nil, nil)", rows, err)
	}
}

func TestParseLinuxLUKS(t *testing.T) {
	const sample = `{"blockdevices":[
		{"name":"sda","fstype":null,"mountpoint":null,"children":[
			{"name":"sda1","fstype":"vfat","mountpoint":"/boot/efi"},
			{"name":"sda2","fstype":"crypto_LUKS","mountpoint":null,"children":[
				{"name":"sda2_crypt","fstype":"ext4","mountpoint":"/"}
			]}
		]}
	]}`
	volumes, err := parseLinuxLUKS(sample)
	if err != nil {
		t.Fatalf("parseLinuxLUKS: %v", err)
	}
	if len(volumes) != 1 {
		t.Fatalf("got %d volumes, want 1 (only the LUKS container): %+v", len(volumes), volumes)
	}
	if volumes[0].MountPoint != "/" || volumes[0].EncryptionType != "luks" || volumes[0].ProtectionStatus != "on" {
		t.Errorf("volume = %+v", volumes[0])
	}
}

func TestParseLinuxLUKS_NoEncryption(t *testing.T) {
	const sample = `{"blockdevices":[{"name":"sda","fstype":"ext4","mountpoint":"/"}]}`
	volumes, err := parseLinuxLUKS(sample)
	if err != nil {
		t.Fatalf("parseLinuxLUKS: %v", err)
	}
	if len(volumes) != 0 {
		t.Errorf("got %d volumes, want 0: %+v", len(volumes), volumes)
	}
}

func TestParseLinuxLUKS_Malformed(t *testing.T) {
	if _, err := parseLinuxLUKS("not json"); err == nil {
		t.Error("expected an error for malformed JSON, got nil")
	}
}

func TestParseFdesetupStatus(t *testing.T) {
	tests := []struct{ in, want string }{
		{"FileVault is On.\n", "on"},
		{"FileVault is Off.\n", "off"},
		{"", "unknown"},
		{"unexpected output", "unknown"},
	}
	for _, tc := range tests {
		if got := parseFdesetupStatus(tc.in); got != tc.want {
			t.Errorf("parseFdesetupStatus(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
