package network

import (
	stdnet "net"
	"strings"

	psnet "github.com/shirou/gopsutil/v4/net"

	"sentinelgo/internal/osinfo/shared"
)

func Get() []shared.NetAdapter {
	ifaces, err := psnet.Interfaces()
	if err != nil {
		return nil
	}
	var adapters []shared.NetAdapter
	for _, iface := range ifaces {
		if !isLoopback(iface) {
			adapters = append(adapters, buildAdapter(iface))
		}
	}
	return adapters
}

func buildAdapter(iface psnet.InterfaceStat) shared.NetAdapter {
	isUp := hasFlag(iface, "up")
	ipv4s, ipv6s, hasRoutableIPv4 := parseAddresses(iface.Addrs)
	adapterType := getAdapterType(iface.Name)

	a := shared.NetAdapter{
		InterfaceName:  iface.Name,
		FriendlyName:   getFriendlyName(iface.Name),
		DeviceName:     getDeviceName(iface.Name),
		AdapterType:    adapterType,
		Status:         adapterStatus(isUp),
		IsConnected:    isUp && hasRoutableIPv4,
		MACAddress:     iface.HardwareAddr,
		Manufacturer:   getAdapterManufacturer(iface.Name),
		SpeedMbps:      getSpeedMbps(iface.Name),
		IPv4Addresses:  ipv4s,
		IPv6Addresses:  ipv6s,
		DefaultGateway: getDefaultGateway(iface.Name),
		DNSServers:     getDNSServers(iface.Name),
	}
	if adapterType == "WiFi" {
		a.WiFi = getWiFiInfo(iface.Name)
	}
	return a
}

func adapterStatus(isUp bool) string {
	if isUp {
		return "Up"
	}
	return "Down"
}

func parseAddresses(addrs []psnet.InterfaceAddr) (ipv4s []shared.IPv4Address, ipv6s []shared.IPv6Address, hasRoutableIPv4 bool) {
	for _, addr := range addrs {
		ip, ipNet, err := stdnet.ParseCIDR(addr.Addr)
		if err != nil {
			ip = stdnet.ParseIP(addr.Addr)
			if ip == nil {
				continue
			}
		}
		if ip.To4() != nil {
			ipv4s = append(ipv4s, makeIPv4Entry(ip, ipNet))
			if !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				hasRoutableIPv4 = true
			}
		} else if ip.To16() != nil {
			ipv6s = append(ipv6s, makeIPv6Entry(ip, ipNet))
		}
	}
	return
}

func makeIPv4Entry(ip stdnet.IP, ipNet *stdnet.IPNet) shared.IPv4Address {
	entry := shared.IPv4Address{Address: ip.String()}
	if ipNet != nil {
		entry.SubnetMask = stdnet.IP(ipNet.Mask).String()
		entry.Subnet = ipNet.IP.String()
	}
	return entry
}

func makeIPv6Entry(ip stdnet.IP, ipNet *stdnet.IPNet) shared.IPv6Address {
	entry := shared.IPv6Address{Address: ip.String()}
	if ipNet != nil {
		entry.PrefixLen, _ = ipNet.Mask.Size()
	}
	return entry
}

func GetPrimaryMACAddress(netInterfaces []psnet.InterfaceStat) string {
	for _, iface := range netInterfaces {
		if iface.HardwareAddr != "" && !strings.HasPrefix(iface.HardwareAddr, "00:00:00") {
			return iface.HardwareAddr
		}
	}
	return ""
}

func isLoopback(iface psnet.InterfaceStat) bool {
	return hasFlag(iface, "loopback")
}

func hasFlag(iface psnet.InterfaceStat, flag string) bool {
	flagL := strings.ToLower(flag)
	for _, f := range iface.Flags {
		if strings.ToLower(f) == flagL {
			return true
		}
	}
	return false
}
