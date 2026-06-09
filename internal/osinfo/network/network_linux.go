package network

import (
	"fmt"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

func getWiFiDevices() map[string]bool {
	return make(map[string]bool)
}

func resolveConnectionName(name string, _ map[string]bool) string {
	nl := strings.ToLower(name)
	switch {
	case strings.HasPrefix(nl, "wlan") || strings.HasPrefix(nl, "wl"):
		return "Wi-Fi"
	case strings.HasPrefix(nl, "eth") || strings.HasPrefix(nl, "em") ||
		strings.HasPrefix(nl, "eno") || strings.HasPrefix(nl, "enp"):
		return "Ethernet"
	default:
		return "Other"
	}
}

func getAdapterManufacturer(name string) string {
	if output, err := shared.ReadFileContent(fmt.Sprintf("/sys/class/net/%s/device/vendor", name)); err == nil {
		vendor := strings.TrimSpace(output)
		if vendor != "" && vendor != "0x0000" {
			return vendor
		}
	}
	return "Unknown"
}
