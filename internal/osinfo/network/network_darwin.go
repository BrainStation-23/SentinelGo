package network

import (
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

func getWiFiDevices() map[string]bool {
	wifiDevices := make(map[string]bool)
	output, err := shared.RunCommand("networksetup", "-listallhardwareports")
	if err != nil {
		return wifiDevices
	}
	isWifi := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Hardware Port:") {
			ll := strings.ToLower(line)
			isWifi = strings.Contains(ll, "wi-fi") || strings.Contains(ll, "wifi") || strings.Contains(ll, "airport")
		} else if strings.HasPrefix(line, "Device:") && isWifi {
			dev := strings.TrimSpace(strings.TrimPrefix(line, "Device:"))
			if dev != "" {
				wifiDevices[dev] = true
			}
		}
	}
	return wifiDevices
}

func resolveConnectionName(name string, wifiDevices map[string]bool) string {
	if wifiDevices[name] {
		return "Wi-Fi"
	}
	if strings.HasPrefix(strings.ToLower(name), "en") {
		return "Ethernet"
	}
	return "Other"
}

func getAdapterManufacturer(_ string) string {
	return "Unknown"
}
