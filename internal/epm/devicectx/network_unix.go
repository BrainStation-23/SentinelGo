//go:build linux || darwin

package devicectx

import (
	"bufio"
	"io"
	"os"
	"strings"
)

func init() {
	dnsSuffixesFn = readResolvConfSuffixes
}

// readResolvConfSuffixes parses /etc/resolv.conf's "search" and "domain"
// directives — the standard resolver config on both Linux and macOS (macOS's
// mDNSResponder keeps it populated even though most users never edit it by
// hand).
func readResolvConfSuffixes() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseResolvConf(f)
}

// parseResolvConf is the pure parsing half of readResolvConfSuffixes, split
// out so it is testable without touching the real filesystem. A single
// "search" line may list multiple suffixes; later directives of either kind
// append rather than replace, matching resolver behavior of "last one wins
// for a single default domain, search list accumulates" closely enough for
// this cheap, best-effort tier — a resolv.conf a rule author actually cares
// about got exercised via CorporateDNSSuffixes membership, not exact
// resolver precedence.
func parseResolvConf(r io.Reader) []string {
	var suffixes []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "search", "domain":
			for _, s := range fields[1:] {
				s = strings.ToLower(strings.TrimSuffix(s, "."))
				if s != "" && !seen[s] {
					seen[s] = true
					suffixes = append(suffixes, s)
				}
			}
		}
	}
	return suffixes
}
