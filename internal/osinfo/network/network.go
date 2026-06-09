package network

import (
	"fmt"
	stdnet "net"
	"strings"

	psnet "github.com/shirou/gopsutil/v3/net"

	"sentinelgo/internal/osinfo/shared"
)

func Get() []shared.NetAdapter {
	var adapters []shared.NetAdapter

	ifaces, err := psnet.Interfaces()
	if err != nil {
		return adapters
	}

	wifiDevices := getWiFiDevices()

	for _, iface := range ifaces {
		if isLoopback(iface) {
			continue
		}

		adapter := shared.NetAdapter{
			Type:         "Physical",
			Description:  iface.Name,
			Manufacturer: getAdapterManufacturer(iface.Name),
			MACAddress:   iface.HardwareAddr,
		}

		for _, flag := range iface.Flags {
			if strings.ToLower(flag) == "up" {
				adapter.IsConnected = true
				break
			}
		}

		for _, addr := range iface.Addrs {
			cidr := addr.Addr
			ip, ipNet, err := stdnet.ParseCIDR(cidr)
			if err != nil {
				ip = stdnet.ParseIP(cidr)
				if ip == nil {
					continue
				}
			}
			if ip.To4() != nil {
				adapter.IPv4 = shared.NetAdapterIPv4{Address: ip.String()}
				if ipNet != nil {
					adapter.IPv4.SubnetMask = stdnet.IP(ipNet.Mask).String()
					adapter.IPv4.Subnet = ipNet.IP.String()
				}
			} else if ip.To16() != nil {
				adapter.IPv6 = shared.NetAdapterIPv6{Address: ip.String()}
				if ipNet != nil {
					ones, _ := ipNet.Mask.Size()
					adapter.IPv6.SubnetMask = fmt.Sprintf("%d", ones)
					adapter.IPv6.Subnet = ipNet.IP.String()
				}
			}
		}

		adapter.ConnectionName = resolveConnectionName(iface.Name, wifiDevices)
		adapters = append(adapters, adapter)
	}
	return adapters
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
	for _, flag := range iface.Flags {
		if strings.ToLower(flag) == "loopback" {
			return true
		}
	}
	return false
}
