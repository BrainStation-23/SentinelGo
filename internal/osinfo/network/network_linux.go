package network

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

func getFriendlyName(name string) string {
	return name
}

func getAdapterType(name string) string {
	nl := strings.ToLower(name)
	switch {
	case strings.HasPrefix(nl, "wlan") || strings.HasPrefix(nl, "wlp") || strings.HasPrefix(nl, "wl"):
		return "WiFi"
	case strings.HasPrefix(nl, "eth") || strings.HasPrefix(nl, "en") || strings.HasPrefix(nl, "em") ||
		strings.HasPrefix(nl, "eno") || strings.HasPrefix(nl, "enp") || strings.HasPrefix(nl, "ens"):
		return "Ethernet"
	case strings.HasPrefix(nl, "lo"):
		return "Loopback"
	case strings.HasPrefix(nl, "tun") || strings.HasPrefix(nl, "tap") || strings.Contains(nl, "vpn"):
		return "VPN"
	case strings.HasPrefix(nl, "veth") || strings.HasPrefix(nl, "docker") ||
		strings.HasPrefix(nl, "br-") || strings.HasPrefix(nl, "virbr"):
		return "Virtual"
	default:
		return "Other"
	}
}

func getSpeedMbps(name string) int64 {
	data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/speed", name))
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func getDefaultGateway(name string) string {
	output, err := shared.RunCommand("ip", "route", "show", "dev", name)
	if err != nil {
		return ""
	}
	return parseDefaultGatewayFromIPRoute(output)
}

func parseDefaultGatewayFromIPRoute(output string) string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "default" && fields[1] == "via" && isIPAddress(fields[2]) {
			return fields[2]
		}
	}
	return ""
}

func getDNSServers(_ string) []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	return parseDNSServersFromResolvConf(string(data))
}

func parseDNSServersFromResolvConf(content string) []string {
	var servers []string
	for _, line := range strings.Split(content, "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[0] == "nameserver" && isIPAddress(parts[1]) {
			servers = append(servers, parts[1])
		}
	}
	return servers
}

func getDeviceName(_ string) string {
	return ""
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

func getWiFiInfo(name string) *shared.WiFiInfo {
	output, err := shared.RunCommand("iw", "dev", name, "link")
	if err != nil {
		return nil
	}
	return parseWiFiInfoFromIW(output)
}

func parseWiFiInfoFromIW(output string) *shared.WiFiInfo {
	info := &shared.WiFiInfo{}
	for _, line := range strings.Split(output, "\n") {
		applyIWLine(info, strings.TrimSpace(line))
	}
	if info.SSID == "" {
		return nil
	}
	return info
}

// applyIWLine applies a single line of `iw dev <name> link` output to info.
func applyIWLine(info *shared.WiFiInfo, line string) {
	switch {
	case strings.HasPrefix(line, "SSID:"):
		info.SSID = strings.TrimSpace(strings.TrimPrefix(line, "SSID:"))
	case strings.Contains(line, "signal:"):
		applyIWSignalField(info, line)
	case strings.Contains(line, "freq:"):
		applyIWFreqField(info, line)
	}
}

// applyIWSignalField extracts the "signal: <dBm>" field from an `iw` line.
func applyIWSignalField(info *shared.WiFiInfo, line string) {
	fields := strings.Fields(line)
	for i, f := range fields {
		if f == "signal:" && i+1 < len(fields) {
			if n, err := strconv.Atoi(fields[i+1]); err == nil {
				info.SignalStrength = n
			}
		}
	}
}

// applyIWFreqField extracts the "freq: <MHz>" field from an `iw` line.
func applyIWFreqField(info *shared.WiFiInfo, line string) {
	fields := strings.Fields(line)
	for i, f := range fields {
		if f == "freq:" && i+1 < len(fields) {
			info.FrequencyBand = freqMHzToBand(fields[i+1])
		}
	}
}

func freqMHzToBand(mhzStr string) string {
	mhz, err := strconv.Atoi(mhzStr)
	if err != nil {
		return ""
	}
	switch {
	case mhz >= 2400 && mhz < 2500:
		return "2.4GHz"
	case mhz >= 5000 && mhz < 6000:
		return "5GHz"
	case mhz >= 6000:
		return "6GHz"
	}
	return ""
}
