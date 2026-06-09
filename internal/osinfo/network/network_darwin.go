package network

import (
	"strconv"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// hardwarePortMap builds interface→friendly-name and interface→service-name maps
// from `networksetup -listallhardwareports`.
func hardwarePortMap() (friendlyNames map[string]string, serviceNames map[string]string) {
	output, err := shared.RunCommand("networksetup", "-listallhardwareports")
	if err != nil {
		return make(map[string]string), make(map[string]string)
	}
	return parseHardwarePorts(output)
}

func parseHardwarePorts(output string) (friendlyNames map[string]string, serviceNames map[string]string) {
	friendlyNames = make(map[string]string)
	serviceNames = make(map[string]string)
	var currentPort, currentDev string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Hardware Port:") {
			currentPort = strings.TrimSpace(strings.TrimPrefix(line, "Hardware Port:"))
			currentDev = ""
		} else if strings.HasPrefix(line, "Device:") {
			currentDev = strings.TrimSpace(strings.TrimPrefix(line, "Device:"))
			if currentDev != "" && currentPort != "" {
				friendlyNames[currentDev] = currentPort
				serviceNames[currentDev] = currentPort
			}
		}
	}
	return
}

func getFriendlyName(name string) string {
	friendly, _ := hardwarePortMap()
	if v, ok := friendly[name]; ok {
		return v
	}
	return name
}

func getAdapterType(name string) string {
	friendly, _ := hardwarePortMap()
	label := strings.ToLower(friendly[name])
	nl := strings.ToLower(name)
	switch {
	case strings.Contains(label, "wi-fi") || strings.Contains(label, "wifi") || strings.Contains(label, "airport"):
		return "WiFi"
	case strings.Contains(label, "ethernet") || strings.Contains(label, "thunderbolt"):
		return "Ethernet"
	case strings.Contains(label, "bluetooth"):
		return "Bluetooth"
	case strings.HasPrefix(nl, "utun") || strings.HasPrefix(nl, "tun") || strings.HasPrefix(nl, "tap"):
		return "VPN"
	case strings.HasPrefix(nl, "lo"):
		return "Loopback"
	case strings.HasPrefix(nl, "bridge") || strings.HasPrefix(nl, "vmnet"):
		return "Virtual"
	default:
		return "Other"
	}
}

func getSpeedMbps(name string) int64 {
	_, services := hardwarePortMap()
	svc, ok := services[name]
	if !ok {
		return 0
	}
	output, err := shared.RunCommand("networksetup", "-getinfo", svc)
	if err != nil {
		return 0
	}
	return parseSpeedMbpsFromNetworksetup(output)
}

func parseSpeedMbpsFromNetworksetup(output string) int64 {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Link Speed:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "Link Speed:"))
			parts := strings.Fields(val)
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
	output, err := shared.RunCommand("netstat", "-nr", "-f", "inet")
	if err != nil {
		return ""
	}
	return parseDefaultGatewayFromNetstat(output, name)
}

func parseDefaultGatewayFromNetstat(output, ifaceName string) string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		// columns: Destination Gateway Flags Refs Use Netif
		if len(fields) >= 6 && fields[0] == "default" && fields[5] == ifaceName {
			return fields[1]
		}
	}
	return ""
}

func getDNSServers(name string) []string {
	_, services := hardwarePortMap()
	svc, ok := services[name]
	if !ok {
		return nil
	}
	output, err := shared.RunCommand("networksetup", "-getdnsservers", svc)
	if err != nil {
		return nil
	}
	return parseDNSServersOutput(output)
}

func parseDNSServersOutput(output string) []string {
	var servers []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.Contains(line, "aren't") && !strings.Contains(line, "There") {
			servers = append(servers, line)
		}
	}
	return servers
}

func getAdapterManufacturer(_ string) string {
	return "Unknown"
}

func getWiFiInfo(name string) *shared.WiFiInfo {
	const airportPath = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
	output, err := shared.RunCommand(airportPath, "-I")
	if err != nil {
		return nil
	}
	_ = name // airport -I reports the single active Wi-Fi interface
	return parseAirportInfo(output)
}

func parseAirportInfo(output string) *shared.WiFiInfo {
	info := &shared.WiFiInfo{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		switch key {
		case "SSID":
			info.SSID = val
		case "agrCtlRSSI", "RSSI":
			if n, err := strconv.Atoi(val); err == nil {
				info.SignalStrength = n
			}
		case "channel":
			ch := strings.Split(val, ",")[0]
			if n, err := strconv.Atoi(ch); err == nil {
				info.FrequencyBand = bandFromChannel(n)
			}
		}
	}
	if info.SSID == "" {
		return nil
	}
	return info
}

func bandFromChannel(ch int) string {
	switch {
	case ch >= 1 && ch <= 14:
		return "2.4GHz"
	case ch >= 36 && ch <= 177:
		return "5GHz"
	case ch > 177:
		return "6GHz"
	}
	return ""
}
