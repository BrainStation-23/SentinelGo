package security

import (
	"net/netip"
	"testing"
)

// TestInterfaceOfAddr: every host has 127.0.0.1 on its loopback interface,
// and nothing holds a TEST-NET-1 address.
func TestInterfaceOfAddr(t *testing.T) {
	loopback := netip.MustParseAddr("127.0.0.1")
	if idx, ok := systemInterfaceIndex(loopback); !ok || idx <= 0 {
		t.Errorf("systemInterfaceIndex(127.0.0.1) = %d, %v; want the loopback interface", idx, ok)
	}
	if name, ok := systemInterfaceName(loopback); !ok || name == "" {
		t.Errorf("systemInterfaceName(127.0.0.1) = %q, %v; want the loopback interface", name, ok)
	}
	unused := netip.MustParseAddr("192.0.2.123")
	if _, ok := systemInterfaceIndex(unused); ok {
		t.Error("found an interface for a TEST-NET-1 address")
	}
}
