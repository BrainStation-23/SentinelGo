package uploadproxy

// The proxy auto-config (PAC) script the system proxy setting points at
// (#344 phase 2): only the destinations in scope go to the local proxy, and
// with "; DIRECT" after it, so a browser goes direct when the proxy is down
// (fail open). Everything else, and every bypass host, is DIRECT.

import (
	"fmt"
	"net/url"
	"strings"
)

// pacPath is where the proxy serves the script.
const pacPath = "/proxy.pac"

// PACURL is the auto-config URL for a proxy listening on addr. It is plain
// HTTP on purpose: the proxy listens on loopback only (requireLoopback,
// Service), the script holds no secret, and system proxy settings fetch
// auto-config over HTTP (an HTTPS URL would need a certificate the OS
// trusts before the proxy that serves it is set up).
func PACURL(addr string) string {
	return (&url.URL{Scheme: "http", Host: addr, Path: pacPath}).String()
}

// Scope is the proxy's scope for intercept and bypass host lists: in
// intercept, not in bypass, on 443 or 80. Lists are host names or
// "*.example.com" patterns (validated by the policy).
func Scope(intercept, bypass []string) func(host, port string) bool {
	in, out := HostScope(intercept), HostScope(bypass)
	return func(host, port string) bool { return in(host, port) && !out(host, port) }
}

// BuildPAC writes the script for the proxy at addr. Hosts come from the
// policy, which keeps only plain host patterns, so they are safe inside JS
// string literals; anything else is skipped here too.
func BuildPAC(addr string, intercept, bypass []string) []byte {
	var b strings.Builder
	b.WriteString("// SentinelOps upload inspection: only these destinations go through the local proxy.\n")
	b.WriteString("function FindProxyForURL(url, host) {\n\thost = host.toLowerCase();\n")
	b.WriteString("\tif (url.substring(0, 6) != \"https:\" && url.substring(0, 5) != \"http:\") return \"DIRECT\";\n")
	writeMatches(&b, bypass, "DIRECT")
	writeMatches(&b, intercept, fmt.Sprintf("PROXY %s; DIRECT", addr))
	b.WriteString("\treturn \"DIRECT\";\n}\n")
	return []byte(b.String())
}

func writeMatches(b *strings.Builder, hosts []string, result string) {
	for _, h := range hosts {
		if !pacSafe(h) {
			continue
		}
		if name, ok := strings.CutPrefix(h, "*."); ok {
			fmt.Fprintf(b, "\tif (dnsDomainIs(host, \".%s\")) return %q;\n", name, result)
			continue
		}
		fmt.Fprintf(b, "\tif (host == \"%s\") return %q;\n", h, result)
	}
}

// pacSafe allows only what a host pattern can contain.
func pacSafe(h string) bool {
	if h == "" {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' && c != '*' {
			return false
		}
	}
	return true
}
