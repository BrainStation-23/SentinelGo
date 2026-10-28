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

// netInterface is what systemInterfaceAddrs needs of a net.Interface.
type netInterface struct {
	name  string
	up    bool
	addrs []net.Addr
}

// listInterfaces lists the host's interfaces; swapped in tests.
var listInterfaces = func() ([]netInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]netInterface, 0, len(ifaces))
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		out = append(out, netInterface{name: iface.Name, up: iface.Flags&net.FlagUp != 0, addrs: addrs})
	}
	return out, nil
}

// systemInterfaceAddrs lists the addresses of the host's interfaces that are
// up; nil when they can't be listed.
func systemInterfaceAddrs() []hostAddr {
	ifaces, err := listInterfaces()
	if err != nil {
		return nil
	}
	var out []hostAddr
	for _, iface := range ifaces {
		if !iface.up {
			continue
		}
		for _, a := range iface.addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(ipnet.IP); ok {
					out = append(out, hostAddr{iface: iface.name, addr: ip.Unmap()})
				}
			}
		}
	}
	return out
}
