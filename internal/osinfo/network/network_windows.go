package network

import "strings"

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

func getAdapterManufacturer(_ string) string {
	return "Unknown"
}
