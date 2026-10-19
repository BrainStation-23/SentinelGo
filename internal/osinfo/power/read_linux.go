package power

// powerSupplyRoot is where the kernel lists power supplies; a variable so
// tests can point it at a fixture.
var powerSupplyRoot = "/sys/class/power_supply"

// ReadPower reads the power supplies under /sys/class/power_supply (plain
// file reads, no process).
var ReadPower = func() Reading {
	return linuxPowerReading(readLinuxSupplies(powerSupplyRoot))
}
