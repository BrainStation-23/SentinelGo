package uploadproxy

// The Linux backstop's nftables ruleset (#426 step 2), built here and run
// by the `nft` command in nft_linux.go (no netlink dependency). Everything
// lives in one table of our own, replaced in a single transaction and
// deleted to undo, so it never touches anyone else's rules.
//
// In the output hook, for the addresses of the intercepted hosts:
//
//   - UDP 443 is refused (quic and strict): QUIC falls back to TCP;
//   - TCP 443 (strict only) is redirected to the proxy's transparent
//     listeners, which decrypt the intercepted hosts and splice every other
//     site through untouched. Without a listener for that address family,
//     TCP 443 is refused instead, like WFP on Windows.
//
// The proxy's own connections carry proxyMark and are let through first,
// so they never loop back into it.

import (
	"fmt"
	"net/netip"
	"strings"
)

// nftTable is the agent's table (family inet: IPv4 and IPv6).
const nftTable = "sentinelgo_upload"

// proxyMark is the SO_MARK on the proxy's own connections. Low bits only,
// clear of the 0xff0000 range Tailscale uses and of WireGuard's 0xca6c.
const proxyMark uint32 = 0x5347

// RedirectPorts are the loopback ports of the proxy's transparent listeners
// (Linux), where the backstop sends redirected TCP; 0 means none for that
// address family.
type RedirectPorts struct{ V4, V6 uint16 }

// TCP actions in the status (DirectBlockStatus.TCP).
const (
	TCPRefuse   = "refuse"
	TCPRedirect = "redirect"
)

// nftTCPAction is what strict does to TCP 443 with these ports: redirect
// when both families have a listener, else refuse (for at least one).
func nftTCPAction(p RedirectPorts) string {
	if p.V4 != 0 && p.V6 != 0 {
		return TCPRedirect
	}
	return TCPRefuse
}

// nftScript is the whole table for addrs: deleting the old one and adding
// the new one in one `nft -f` transaction ("table … {}" first, so the
// delete works when there is none yet).
func nftScript(addrs []netip.Addr, tcp bool, ports RedirectPorts) string {
	var v4, v6 []string
	for _, a := range addrs {
		a = a.Unmap()
		if a.Is4() {
			v4 = append(v4, a.String())
		} else {
			v6 = append(v6, a.String())
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {}\ndelete table inet %s\n", nftTable, nftTable)
	fmt.Fprintf(&b, "table inet %s {\n", nftTable)
	writeNftSet(&b, "v4", "ipv4_addr", v4)
	writeNftSet(&b, "v6", "ipv6_addr", v6)

	b.WriteString("\tchain out {\n\t\ttype filter hook output priority 0; policy accept;\n")
	fmt.Fprintf(&b, "\t\tmeta mark 0x%x return\n", proxyMark)
	b.WriteString("\t\tip daddr @v4 udp dport 443 reject\n")
	b.WriteString("\t\tip6 daddr @v6 udp dport 443 reject\n")
	if tcp {
		if ports.V4 == 0 {
			b.WriteString("\t\tip daddr @v4 tcp dport 443 reject with tcp reset\n")
		}
		if ports.V6 == 0 {
			b.WriteString("\t\tip6 daddr @v6 tcp dport 443 reject with tcp reset\n")
		}
	}
	b.WriteString("\t}\n")

	if tcp && (ports.V4 != 0 || ports.V6 != 0) {
		b.WriteString("\tchain nat_out {\n\t\ttype nat hook output priority -100; policy accept;\n")
		fmt.Fprintf(&b, "\t\tmeta mark 0x%x return\n", proxyMark)
		if ports.V4 != 0 {
			fmt.Fprintf(&b, "\t\tip daddr @v4 tcp dport 443 redirect to :%d\n", ports.V4)
		}
		if ports.V6 != 0 {
			fmt.Fprintf(&b, "\t\tip6 daddr @v6 tcp dport 443 redirect to :%d\n", ports.V6)
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func writeNftSet(b *strings.Builder, name, typ string, elems []string) {
	fmt.Fprintf(b, "\tset %s {\n\t\ttype %s;\n", name, typ)
	if len(elems) > 0 {
		fmt.Fprintf(b, "\t\telements = { %s }\n", strings.Join(elems, ", "))
	}
	b.WriteString("\t}\n")
}

// nftRemoveScript deletes the table, and is fine when there is none.
func nftRemoveScript() string {
	return fmt.Sprintf("table inet %s {}\ndelete table inet %s\n", nftTable, nftTable)
}
