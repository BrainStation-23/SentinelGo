package security

// Fuzz target for the firewall and exposure parsers (#221). They read tool
// output and files the agent doesn't control (ufw status, ufw application
// profiles, firewall-cmd, firewalld service XML, the Windows firewall probe,
// socketfilterfw, socket addresses), so parsing and evaluating them must
// never panic on unexpected input.
//
// The seed corpus runs as an ordinary unit test under `go test ./...`.
// To fuzz: go test -run='^$' -fuzz='^FuzzFirewallParsers$' -fuzztime=1m ./internal/osinfo/security/

import (
	"net/netip"
	"strings"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

func FuzzFirewallParsers(f *testing.F) {
	for _, s := range []string{
		ufwVerboseFixture, ufwAppFixture, firewalldFixture, winFwFixture,
		"", "\n", "--", ":", "(v6)", " on ", "[", "[]", "{", "null", `{"profiles":[{}]}`,
		"Status: active\nDefault: allow (incoming)\n--\nAnywhere  ALLOW IN  Anywhere\n",
		"Status: active\n--\n10.0.0.0/33 22/tcp  DENY IN  Anywhere\n",
		"Status: active\n--\n22:1/tcp on  ALLOW IN  ::/0 (v6)\n",
		"[x]\nports=1:99999/tcp|a,b/udp|/", "public (active)\n\trule port port=\"1-0\" protocol=\"tcp\" accept",
		"z\n  interfaces: \n  sources: \n  rich rules: \n\trule family=\"ipv4\" accept",
		`<service><port protocol="tcp" port="99999"/><port protocol="udp" port="-"/></service>`,
		`{"rules":[{"id":"a","action":"Allow","profile":-1}],"ports":[{"id":"a","protocol":"6","local_port":"1-,-2,x"}],"apps":[{"id":"a","program":"\\"}],"profiles":[{"name":"Public","enabled":true}],"networks":[{"index":-1,"category":"Public"}]}`,
		"Block all ENABLED!", "(State = 2)", "0.0.0.0", "::", "[::1]", "fe80::1%", "*", "localhost",
		strings.Repeat("22/tcp  ALLOW IN  Anywhere\n", 200),
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		ports := []shared.ListeningPort{
			{Protocol: "tcp", Port: 445, Address: s, ProcessName: s},
			{Protocol: "udp", Port: 137, Address: "0.0.0.0"},
			{Protocol: "tcp", Port: 22, Address: "10.0.0.5", ProcessName: "sshd"},
		}
		anyIface := func(netip.Addr) (int, bool) { return 1, true }
		anyName := func(netip.Addr) (string, bool) { return s, true }
		resolve := func(name string) ([]portSpec, bool) { return parseFirewalldService([]byte(s)) }

		checks := []firewallCheck{
			parseUFWStatus(s).check(parseUFWAppProfiles([]string{s})),
			firewalldCheck(parseFirewalldZones(s), resolve, anyName),
		}
		if fw, ok := parseWinFirewall(s); ok {
			_ = fw.networkProfiles()
			checks = append(checks, fw.checker(anyIface), fw.checker(nil))
		}
		for _, check := range checks {
			info := analyzeNetworkExposure(ports, check)
			_, _ = summarizeNetworkExposureLevel(info)
		}
		_ = alfBlocksAll(s, s)
		_, _ = listenerFamilies(s)
		_ = bindScope(s)
		_, _ = parsePortList(s, ":")
		_, _ = parsePortList(s, "-")
	})
}
