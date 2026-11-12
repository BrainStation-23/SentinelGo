package uploadproxy

import (
	"net/netip"
	"strings"
	"testing"
)

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

// quic: UDP 443 refused, no TCP rule and no NAT chain; the proxy's own
// connections are let through first; the old table goes in the same run.
func TestNftScript_QUIC(t *testing.T) {
	s := nftScript(addrs("203.0.113.7", "::ffff:198.51.100.1", "2001:db8::1"), false, RedirectPorts{V4: 40001, V6: 40002})
	for _, want := range []string{
		"table inet sentinelgo_upload {}\ndelete table inet sentinelgo_upload\ntable inet sentinelgo_upload {",
		"elements = { 203.0.113.7, 198.51.100.1 }",
		"elements = { 2001:db8::1 }",
		"type filter hook output priority 0; policy accept;\n\t\tmeta mark 0x5347 return\n",
		"ip daddr @v4 udp dport 443 reject",
		"ip6 daddr @v6 udp dport 443 reject",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	if strings.Contains(s, "tcp") || strings.Contains(s, "nat") {
		t.Errorf("quic touches TCP:\n%s", s)
	}
}

// strict with both listeners: TCP 443 redirected per family, never refused,
// and the NAT chain lets the proxy's own connections through too.
func TestNftScript_StrictRedirects(t *testing.T) {
	s := nftScript(addrs("203.0.113.7", "2001:db8::1"), true, RedirectPorts{V4: 40001, V6: 40002})
	for _, want := range []string{
		"type nat hook output priority -100; policy accept;\n\t\tmeta mark 0x5347 return\n",
		"ip daddr @v4 tcp dport 443 redirect to :40001",
		"ip6 daddr @v6 tcp dport 443 redirect to :40002",
		"ip daddr @v4 udp dport 443 reject",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	if strings.Contains(s, "tcp reset") {
		t.Errorf("strict with listeners refuses TCP:\n%s", s)
	}
	if got := nftTCPAction(RedirectPorts{V4: 1, V6: 2}); got != TCPRedirect {
		t.Errorf("action %q", got)
	}
}

// strict without an IPv6 listener refuses IPv6 TCP and still redirects
// IPv4; without any listener there is no NAT chain at all.
func TestNftScript_StrictWithoutListener(t *testing.T) {
	s := nftScript(addrs("203.0.113.7", "2001:db8::1"), true, RedirectPorts{V4: 40001})
	if !strings.Contains(s, "ip6 daddr @v6 tcp dport 443 reject with tcp reset") || !strings.Contains(s, "redirect to :40001") ||
		strings.Contains(s, "ip daddr @v4 tcp dport 443 reject") {
		t.Errorf("script:\n%s", s)
	}
	s = nftScript(addrs("203.0.113.7"), true, RedirectPorts{})
	if strings.Contains(s, "nat") || !strings.Contains(s, "ip daddr @v4 tcp dport 443 reject with tcp reset") {
		t.Errorf("script:\n%s", s)
	}
	if got := nftTCPAction(RedirectPorts{V4: 1}); got != TCPRefuse {
		t.Errorf("action %q", got)
	}
}

// No addresses: empty sets (nft rejects an empty elements list).
func TestNftScript_Empty(t *testing.T) {
	s := nftScript(nil, true, RedirectPorts{V4: 1, V6: 2})
	if strings.Contains(s, "elements") || !strings.Contains(s, "set v4 {\n\t\ttype ipv4_addr;\n\t}") {
		t.Errorf("script:\n%s", s)
	}
	if r := nftRemoveScript(); r != "table inet sentinelgo_upload {}\ndelete table inet sentinelgo_upload\n" {
		t.Errorf("remove %q", r)
	}
}
