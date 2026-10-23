package security

import (
	"net"
	"net/netip"
)

// interfaceOfAddr returns the network interface that holds addr, used to
// find which network (and so which firewall profile or zone) governs a
// socket bound to one interface's address.
func interfaceOfAddr(addr netip.Addr) (net.Interface, bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, false
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ip, ok := netip.AddrFromSlice(ipnet.IP); ok && ip.Unmap() == addr {
				return iface, true
			}
		}
	}
	return net.Interface{}, false
}

// systemInterfaceIndex is the interfaceIndexFunc for this host.
func systemInterfaceIndex(addr netip.Addr) (int, bool) {
	iface, ok := interfaceOfAddr(addr)
	return iface.Index, ok
}

// systemInterfaceName returns the name of the interface holding addr.
func systemInterfaceName(addr netip.Addr) (string, bool) {
	iface, ok := interfaceOfAddr(addr)
	return iface.Name, ok
}
