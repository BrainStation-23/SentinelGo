package directory

import "strings"

// parseDsregcmd extracts Entra ID (Azure AD) join fields from `dsregcmd
// /status` output.
//
// On-prem Active Directory join state comes from WMI instead (see
// directory_windows.go): dsregcmd's device-state table has changed shape
// across Windows versions and its DomainJoined line is redundant with the WMI
// field, so only the Entra-specific fields — which have no other source — are
// parsed here.
//
// No build tag: this is plain text parsing, exercised the same way whether
// the sample text came from a live dsregcmd run or a fixture, so it is unit
// tested on every host regardless of GOOS.
func parseDsregcmd(output string) (entraJoined bool, tenantID, deviceID string) {
	fields := parseColonTable(output)
	entraJoined = strings.EqualFold(fields["azureadjoined"], "YES")
	tenantID = fields["tenantid"]
	deviceID = fields["deviceid"]
	return entraJoined, tenantID, deviceID
}

// parseColonTable parses dsregcmd's right-aligned "  Key : Value" lines into
// a lowercase-keyed map. Border and header lines (no colon) are skipped.
func parseColonTable(output string) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		val := strings.TrimSpace(line[idx+1:])
		if key == "" || val == "" {
			continue
		}
		out[key] = val
	}
	return out
}

// parseRealmList parses `realm list` output. A joined domain appears as an
// unindented header line ("example.com") followed by indented "key: value"
// detail lines; an unjoined host produces no output at all.
func parseRealmList(output string) (domainJoined bool, domain string) {
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			return true, strings.TrimSpace(line)
		}
	}
	return false, ""
}

// parseSSSDConfig extracts the first configured domain from sssd.conf's
// `domains = ` line under [sssd]. This is a weaker signal than realm's live
// join state — it reports what sssd is configured for, not a confirmed
// active join — used only as a fallback when realmd tooling is not
// installed, per docs/telemetry/03-collection-matrix.md.
func parseSSSDConfig(content string) (domainJoined bool, domain string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(line), "domains") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		val := strings.TrimSpace(line[idx+1:])
		if val == "" {
			continue
		}
		first := strings.TrimSpace(strings.Split(val, ",")[0])
		if first != "" {
			return true, first
		}
	}
	return false, ""
}

// parseDsconfigad parses `dsconfigad -show` output for the joined Active
// Directory domain, reported as "Active Directory Domain = example.com".
func parseDsconfigad(output string) (domainJoined bool, domain string) {
	for _, line := range strings.Split(output, "\n") {
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		val := strings.TrimSpace(line[idx+1:])
		if key == "active directory domain" && val != "" {
			return true, val
		}
	}
	return false, ""
}
