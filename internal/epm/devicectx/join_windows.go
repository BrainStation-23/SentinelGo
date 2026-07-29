//go:build windows

package devicectx

import (
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"

	"sentinelgo/internal/epm"
	"sentinelgo/internal/osinfo/shared"
)

// collectJoinReal shells out to `dsregcmd /status` for AzureAdJoined,
// DomainJoined, and TenantId — a single, deliberately minimal check (see
// join.go's doc comment for why this isn't the fuller
// NetGetJoinInformation + CloudDomainJoin-registry design the original
// sketch considered). dsregcmd does not reliably print the joined AD
// domain's *name* in a stable, parseable field across Windows versions, so
// domain name is read separately from the registry key that AD-join itself
// populates (Tcpip\Parameters\Domain) — the same key network_windows.go
// reads for DNS suffixes, but read independently here since these are
// conceptually different lookups that happen to share a source.
func collectJoinReal() joinResult {
	out, exitCode, err := shared.RunCommandOutput("dsregcmd", "/status")
	if err != nil {
		return joinResult{ok: false, errMsg: err.Error()}
	}
	if exitCode != 0 {
		return joinResult{ok: false, errMsg: "dsregcmd /status exited " + strconv.Itoa(exitCode)}
	}

	fields := parseDsregcmdFields(out)
	res := joinResult{
		ok:           true,
		domainJoined: triFromYesNo(fields["domainjoined"]),
		entraJoined:  triFromYesNo(fields["azureadjoined"]),
		tenantID:     fields["tenantid"],
		domainName:   readWindowsDomainName(),
	}
	return res
}

// parseDsregcmdFields parses dsregcmd's "  Key : Value" box-drawn output
// into a lowercased, space-stripped key map.
func parseDsregcmdFields(out string) map[string]string {
	fields := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(parts[0]), " ", ""))
		if key == "" {
			continue
		}
		fields[key] = strings.TrimSpace(parts[1])
	}
	return fields
}

func triFromYesNo(v string) epm.Tri {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "YES":
		return epm.TriTrue
	case "NO":
		return epm.TriFalse
	default:
		return epm.TriUnknown
	}
}

// readWindowsDomainName reads the AD domain a joined machine's TCP/IP stack
// was configured with — set by the domain-join process itself, so its
// presence/absence tracks DomainJoined closely without needing a second
// subprocess call.
func readWindowsDomainName() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("Domain")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}
