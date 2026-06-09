package network

import (
	"strconv"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

func getFriendlyName(name string) string {
	// On Windows, gopsutil already returns the user-visible adapter name (e.g. "Wi-Fi", "Ethernet 2").
	return name
}

func getAdapterType(name string) string {
	nl := strings.ToLower(name)
	switch {
	case strings.HasPrefix(nl, "wi-fi") || strings.HasPrefix(nl, "wlan") || strings.HasPrefix(nl, "wireless"):
		return "WiFi"
	case strings.HasPrefix(nl, "ethernet") || strings.HasPrefix(nl, "local area connection"):
		return "Ethernet"
	case strings.Contains(nl, "loopback") || nl == "lo":
		return "Loopback"
	case strings.Contains(nl, "vpn") || strings.Contains(nl, "tunnel") || strings.HasPrefix(nl, "tun") || strings.HasPrefix(nl, "tap"):
		return "VPN"
	case strings.Contains(nl, "virtual") || strings.Contains(nl, "vmware") || strings.Contains(nl, "hyper-v") || strings.Contains(nl, "vethernet"):
		return "Virtual"
	case strings.HasPrefix(nl, "bluetooth"):
		return "Bluetooth"
	default:
		return "Other"
	}
}

func getSpeedMbps(name string) int64 {
	output, err := shared.RunCommand("netsh", "interface", "show", "interface", "name="+name)
	if err != nil {
		return 0
	}
	return parseSpeedMbps(output)
}

func parseSpeedMbps(output string) int64 {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		kv := splitKV(line)
		if kv == nil {
			continue
		}
		k := strings.ToLower(kv[0])
		if strings.Contains(k, "speed") {
			parts := strings.Fields(kv[1])
			if len(parts) >= 2 {
				n, err := strconv.ParseInt(parts[0], 10, 64)
				if err != nil {
					continue
				}
				if strings.HasPrefix(strings.ToLower(parts[1]), "g") {
					return n * 1000
				}
				return n
			}
		}
	}
	return 0
}

func getDefaultGateway(name string) string {
	output, err := shared.RunCommand("netsh", "interface", "ip", "show", "config", "name="+name)
	if err != nil {
		return ""
	}
	return parseDefaultGateway(output)
}

func parseDefaultGateway(output string) string {
	for _, line := range strings.Split(output, "\n") {
		kv := splitKV(strings.TrimSpace(line))
		if kv == nil {
			continue
		}
		if strings.Contains(strings.ToLower(kv[0]), "default gateway") {
			gw := strings.TrimSpace(kv[1])
			if gw != "" && gw != "None" {
				return gw
			}
		}
	}
	return ""
}

func getDNSServers(name string) []string {
	output, err := shared.RunCommand("netsh", "interface", "ip", "show", "dns", "name="+name)
	if err != nil {
		return nil
	}
	return parseDNSServers(output)
}

func parseDNSServers(output string) []string {
	var servers []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		kv := splitKV(line)
		var candidate string
		if kv != nil {
			candidate = strings.TrimSpace(kv[1])
		} else {
			candidate = line
		}
		if isIPAddress(candidate) {
			servers = append(servers, candidate)
		}
	}
	return servers
}

func getAdapterManufacturer(_ string) string {
	return "Unknown"
}

func getWiFiInfo(name string) *shared.WiFiInfo {
	output, err := shared.RunCommand("netsh", "wlan", "show", "interfaces")
	if err != nil {
		return nil
	}
	return parseWiFiInfo(output, name)
}

func parseWiFiInfo(output, ifaceName string) *shared.WiFiInfo {
	for _, block := range splitWlanBlocks(output) {
		if !strings.Contains(strings.ToLower(block), strings.ToLower(ifaceName)) {
			continue
		}
		return parseWiFiBlock(block)
	}
	return nil
}

func parseWiFiBlock(block string) *shared.WiFiInfo {
	info := &shared.WiFiInfo{}
	for _, line := range strings.Split(block, "\n") {
		kv := splitKV(strings.TrimSpace(line))
		if kv == nil {
			continue
		}
		key, val := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		keyL := strings.ToLower(key)
		switch {
		case keyL == "ssid" && !strings.Contains(keyL, "bssid"):
			info.SSID = val
		case strings.Contains(keyL, "signal"):
			pct := strings.TrimSuffix(val, "%")
			if n, err := strconv.Atoi(pct); err == nil {
				info.SignalStrength = (n / 2) - 100
			}
		case strings.Contains(keyL, "radio type") || strings.Contains(keyL, "band"):
			info.FrequencyBand = parseBand(val)
		case strings.Contains(keyL, "channel") && info.FrequencyBand == "":
			info.FrequencyBand = bandFromChannel(val)
		}
	}
	if info.SSID == "" {
		return nil
	}
	return info
}

func splitWlanBlocks(output string) []string {
	var blocks []string
	var cur strings.Builder
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" && cur.Len() > 0 {
			blocks = append(blocks, cur.String())
			cur.Reset()
		} else {
			cur.WriteString(line)
			cur.WriteByte('\n')
		}
	}
	if cur.Len() > 0 {
		blocks = append(blocks, cur.String())
	}
	return blocks
}

// splitKV splits "Key : Value" into ["Key", "Value"]; returns nil if no colon.
func splitKV(line string) []string {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return nil
	}
	key := strings.TrimSpace(line[:idx])
	val := strings.TrimSpace(line[idx+1:])
	if key == "" {
		return nil
	}
	return []string{key, val}
}

func parseBand(radioType string) string {
	rt := strings.ToLower(radioType)
	switch {
	case strings.Contains(rt, "6ghz"):
		return "6GHz"
	case strings.Contains(rt, "5ghz") || strings.Contains(rt, "802.11a") || strings.Contains(rt, "802.11ac") || strings.Contains(rt, "802.11ax"):
		return "5GHz"
	case strings.Contains(rt, "2.4") || strings.Contains(rt, "802.11b") || strings.Contains(rt, "802.11g") || strings.Contains(rt, "802.11n"):
		return "2.4GHz"
	}
	return ""
}

func bandFromChannel(channelStr string) string {
	ch, err := strconv.Atoi(strings.TrimSpace(channelStr))
	if err != nil {
		return ""
	}
	switch {
	case ch <= 14:
		return "2.4GHz"
	case ch <= 177:
		return "5GHz"
	default:
		return "6GHz"
	}
}

func isIPAddress(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, " \t") {
		return false
	}
	return strings.ContainsAny(s, ".:")
}
