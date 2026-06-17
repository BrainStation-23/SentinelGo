package system

import (
	"fmt"
	"os"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

func getHardwareModel() string {
	for _, path := range []string{
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/board_name",
		"/sys/class/dmi/id/chassis_type",
	} {
		if model, err := shared.ReadFileContent(path); err == nil && model != "" {
			return strings.TrimSpace(model)
		}
	}
	hostname, _ := os.Hostname()
	return hostname
}

func getSerialNumber() string {
	type candidate struct {
		path    string
		invalid []string
	}
	candidates := []candidate{
		{"/sys/class/dmi/id/product_serial", []string{"Not Specified", "Default String", "0123456789"}},
		{"/sys/class/dmi/id/chassis_serial", []string{"Not Specified", "Default String"}},
		{"/sys/class/dmi/id/board_serial", []string{"Not Specified", "Default String"}},
		{"/etc/machine-id", nil},
		{"/var/lib/dbus/machine-id", nil},
	}
	for _, c := range candidates {
		serial, err := shared.ReadFileContent(c.path)
		if err != nil || serial == "" {
			continue
		}
		serial = strings.TrimSpace(serial)
		invalid := false
		for _, bad := range c.invalid {
			if serial == bad {
				invalid = true
				break
			}
		}
		if !invalid && serial != "" {
			return serial
		}
	}
	if output, err := shared.RunCommand("dmidecode", "-s", "system-serial-number"); err == nil {
		serial := strings.TrimSpace(output)
		if serial != "" && serial != "Not Specified" && serial != "Default String" {
			return serial
		}
	}
	hostname, _ := os.Hostname()
	return hostname
}

func getBatteryCondition() string {
	for _, bat := range []string{"BAT0", "BAT1"} {
		status, err := shared.ReadFileContent("/sys/class/power_supply/" + bat + "/status")
		if err != nil {
			continue
		}
		status = strings.TrimSpace(status)
		if status == "" {
			continue
		}
		if capacity, err := shared.ReadFileContent("/sys/class/power_supply/" + bat + "/capacity"); err == nil {
			return fmt.Sprintf("%s (%s%%)", status, strings.TrimSpace(capacity))
		}
		return status
	}
	return "No Battery"
}

func getFQDN() string {
	if output, err := shared.RunCommand("hostname", "-f"); err == nil {
		if fqdn := strings.TrimSpace(output); fqdn != "" {
			return fqdn
		}
	}
	h, _ := os.Hostname()
	return h
}

func getChassisType() string {
	typeCode, _ := shared.ReadFileContent("/sys/class/dmi/id/chassis_type")
	productName, _ := shared.ReadFileContent("/sys/class/dmi/id/product_name")
	if result := parseLinuxChassisType(typeCode, productName); result != "" {
		return result
	}
	if containsVM(strings.ToLower(productName)) {
		return "VM"
	}
	return "Other"
}

func getOSInformation() shared.OSInformation {
	osInfo := osInfoBase()
	if content, err := shared.ReadFileContent("/etc/os-release"); err == nil {
		osInfo.OSName, osInfo.OSServicePack = parseOSReleaseContent(content)
	}
	if out, err := shared.RunCommand("uname", "-r"); err == nil {
		osInfo.OSVersion = strings.TrimSpace(out)
	}
	osInfo.OSType = "Linux"
	if osInfo.OSName == "" {
		osInfo.OSName = "Linux"
	}
	return osInfo
}

func getFirmwareInfo() (firmwareType, vendor, version string) {
	if _, err := os.Stat("/sys/firmware/efi"); err == nil {
		firmwareType = "UEFI"
	} else {
		firmwareType = "Legacy BIOS"
	}
	if v, err := shared.ReadFileContent("/sys/class/dmi/id/bios_vendor"); err == nil {
		vendor = strings.TrimSpace(v)
	}
	if v, err := shared.ReadFileContent("/sys/class/dmi/id/bios_version"); err == nil {
		version = strings.TrimSpace(v)
	}
	return
}
