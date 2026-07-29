//go:build windows

package devicectx

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

func init() {
	dnsSuffixesFn = readWindowsDNSSuffixes
}

// readWindowsDNSSuffixes reads the system-wide DNS suffix search list from
// HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters — the same values
// Control Panel's "DNS suffix" and "search list" settings edit. This is the
// system-wide list only; a per-adapter suffix override
// (Tcpip\Parameters\Interfaces\<GUID>\Domain) is not read, a deliberate,
// documented scope reduction for this pass — the system-wide list is what a
// domain-joined corporate machine actually has populated, and per-adapter
// overrides are rare enough that CorporateDNSSuffixes matching degrading to
// "checked the system list" rather than Unknown is an acceptable trade for
// not adding a full adapter-GUID enumeration pass here.
func readWindowsDNSSuffixes() []string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()

	var searchList, domain string
	if v, _, err := k.GetStringValue("SearchList"); err == nil {
		searchList = v
	}
	if v, _, err := k.GetStringValue("Domain"); err == nil {
		domain = v
	}
	return mergeDNSSuffixLists(searchList, domain)
}

// mergeDNSSuffixLists is the pure parsing half of readWindowsDNSSuffixes,
// split out so it is testable without a real registry: SearchList is a
// comma-separated list, Domain is a single value; both are normalized to
// lowercase with any trailing "." stripped, and de-duplicated in
// first-seen order.
func mergeDNSSuffixLists(searchList, domain string) []string {
	var suffixes []string
	seen := make(map[string]bool)
	add := func(raw string) {
		for _, s := range strings.Split(raw, ",") {
			s = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(s, ".")))
			if s != "" && !seen[s] {
				seen[s] = true
				suffixes = append(suffixes, s)
			}
		}
	}
	add(searchList)
	add(domain)
	return suffixes
}
