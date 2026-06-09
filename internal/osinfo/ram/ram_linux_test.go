package ram

import (
	"testing"
)

// sampleDmidecodeOutput returns a representative dmidecode -t memory output
// string for use in unit tests. Individual test cases slice/compose from it.
const singleDDR4Stick = `
Handle 0x0012, DMI type 17, 84 bytes
Memory Device
	Array Handle: 0x0011
	Error Information Handle: 0x0013
	Total Width: 64 bits
	Data Width: 64 bits
	Size: 8 GB
	Form Factor: DIMM
	Set: None
	Locator: ChannelA-DIMM0
	Bank Locator: BANK 0
	Type: DDR4
	Type Detail: Synchronous Unbuffered (Unregistered)
	Speed: 3200 MT/s
	Manufacturer: Samsung
	Serial Number: 12345678
	Asset Tag: Not Provided
	Part Number: M471A1K43DB1-CWE
	Rank: 1
	Configured Memory Speed: 3200 MT/s
	Configured Voltage: 1.2 V
`

const twoDDR4Sticks = `
Handle 0x0012, DMI type 17, 84 bytes
Memory Device
	Size: 8 GB
	Form Factor: DIMM
	Locator: ChannelA-DIMM0
	Bank Locator: BANK 0
	Type: DDR4
	Speed: 3200 MT/s
	Manufacturer: Samsung
	Serial Number: 11111111
	Part Number: M471A1K43DB1-CWE

Handle 0x0014, DMI type 17, 84 bytes
Memory Device
	Size: 8 GB
	Form Factor: DIMM
	Locator: ChannelB-DIMM0
	Bank Locator: BANK 1
	Type: DDR4
	Speed: 3200 MT/s
	Manufacturer: SK Hynix
	Serial Number: 22222222
	Part Number: HMA81GS6AFR8N-UH
`

const withEmptySlot = `
Handle 0x0012, DMI type 17, 84 bytes
Memory Device
	Size: 8 GB
	Form Factor: DIMM
	Locator: ChannelA-DIMM0
	Bank Locator: BANK 0
	Type: DDR4
	Speed: 3200 MT/s
	Manufacturer: Micron
	Serial Number: ABCDEF01
	Part Number: 8ATF1G64HZ-3G2J1

Handle 0x0014, DMI type 17, 84 bytes
Memory Device
	Size: No Module Installed
	Form Factor: DIMM
	Locator: ChannelB-DIMM0
	Bank Locator: BANK 1
	Type: Unknown
	Manufacturer: Not Provided
`

const notProvidedManufacturer = `
Handle 0x0012, DMI type 17, 84 bytes
Memory Device
	Size: 16 GB
	Form Factor: SO-DIMM
	Locator: ChannelA-DIMM0
	Bank Locator: BANK 0
	Type: DDR4
	Speed: 2666 MT/s
	Manufacturer: Not Provided
	Serial Number: Not Specified
	Part Number: Not Specified
`

const lpddr4RowOfChips = `
Handle 0x0012, DMI type 17, 84 bytes
Memory Device
	Size: 16 GB
	Form Factor: Row Of Chips
	Locator: ChannelA-DIMM0
	Bank Locator: BANK 0
	Type: LPDDR4
	Speed: 4267 MT/s
	Manufacturer: SK Hynix
	Serial Number: Not Specified
	Part Number: H9HCNNNCPMMLXR-NEE
`

func TestParseDmidecodeOutput(t *testing.T) {
	const GB = uint64(1024 * 1024 * 1024)

	t.Run("single 8GB DDR4 DIMM", func(t *testing.T) {
		rams, total := parseDmidecodeOutput(singleDDR4Stick)
		if len(rams) != 1 {
			t.Fatalf("expected 1 stick, got %d", len(rams))
		}
		stick := rams[0]
		if stick.Capacity != 8*GB {
			t.Errorf("Capacity = %d, want %d", stick.Capacity, 8*GB)
		}
		if stick.ArchitectureType != "DDR4" {
			t.Errorf("ArchitectureType = %q, want DDR4", stick.ArchitectureType)
		}
		if stick.Manufacturer != "Samsung" {
			t.Errorf("Manufacturer = %q, want Samsung", stick.Manufacturer)
		}
		if stick.Slot != "ChannelA-DIMM0" {
			t.Errorf("Slot = %q, want ChannelA-DIMM0", stick.Slot)
		}
		if stick.FormFactor != "DIMM" {
			t.Errorf("FormFactor = %q, want DIMM", stick.FormFactor)
		}
		if total != 8*GB {
			t.Errorf("TotalCapacity = %d, want %d", total, 8*GB)
		}
	})

	t.Run("two sticks 16GB total", func(t *testing.T) {
		rams, total := parseDmidecodeOutput(twoDDR4Sticks)
		if len(rams) != 2 {
			t.Fatalf("expected 2 sticks, got %d", len(rams))
		}
		if total != 16*GB {
			t.Errorf("TotalCapacity = %d, want %d", total, 16*GB)
		}
		if rams[0].Manufacturer != "Samsung" {
			t.Errorf("stick[0].Manufacturer = %q, want Samsung", rams[0].Manufacturer)
		}
		if rams[1].Manufacturer != "SK Hynix" {
			t.Errorf("stick[1].Manufacturer = %q, want SK Hynix", rams[1].Manufacturer)
		}
	})

	t.Run("empty slot is skipped", func(t *testing.T) {
		rams, total := parseDmidecodeOutput(withEmptySlot)
		if len(rams) != 1 {
			t.Fatalf("expected 1 stick (empty slot skipped), got %d", len(rams))
		}
		if total != 8*GB {
			t.Errorf("TotalCapacity = %d, want %d", total, 8*GB)
		}
	})

	t.Run("Not Provided manufacturer becomes empty string", func(t *testing.T) {
		rams, _ := parseDmidecodeOutput(notProvidedManufacturer)
		if len(rams) != 1 {
			t.Fatalf("expected 1 stick, got %d", len(rams))
		}
		if rams[0].Manufacturer != "" {
			t.Errorf("Manufacturer = %q, want empty string for Not Provided", rams[0].Manufacturer)
		}
		// Serial and Part Number should also be filtered
		if rams[0].Serial != "" {
			t.Errorf("Serial = %q, want empty string for Not Specified", rams[0].Serial)
		}
		if rams[0].Name != "" {
			t.Errorf("Name = %q, want empty string for Not Specified", rams[0].Name)
		}
	})

	t.Run("LPDDR4 Row Of Chips with slot", func(t *testing.T) {
		rams, _ := parseDmidecodeOutput(lpddr4RowOfChips)
		if len(rams) != 1 {
			t.Fatalf("expected 1 stick, got %d", len(rams))
		}
		stick := rams[0]
		if stick.FormFactor != "Row Of Chips" {
			t.Errorf("FormFactor = %q, want Row Of Chips", stick.FormFactor)
		}
		if stick.Slot != "ChannelA-DIMM0" {
			t.Errorf("Slot = %q, want ChannelA-DIMM0", stick.Slot)
		}
		if stick.ArchitectureType != "LPDDR4" {
			t.Errorf("ArchitectureType = %q, want LPDDR4", stick.ArchitectureType)
		}
		if stick.Manufacturer != "SK Hynix" {
			t.Errorf("Manufacturer = %q, want SK Hynix", stick.Manufacturer)
		}
	})
}

func TestGetRAMs_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	info := Get()
	if len(info.RAMs) == 0 {
		t.Fatal("Get() returned no RAM sticks")
	}
	for i, stick := range info.RAMs {
		if stick.Capacity == 0 {
			t.Errorf("RAM stick %d has zero Capacity", i)
		}
		t.Logf("stick[%d]: %+v", i, stick)
	}
}
