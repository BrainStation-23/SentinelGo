package security

// Windows compliance parsers. No OS suffix so they are tested everywhere;
// compliance_windows.go calls them.

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

// parseSeceditPasswordPolicy reads the [System Access] section of a
// `secedit /export /areas SECURITYPOLICY` file. Its keys are not localised,
// unlike `net accounts` output. MaximumPasswordAge is -1 when passwords
// never expire, which the contract writes as 0.
func parseSeceditPasswordPolicy(content string) *shared.PasswordPolicyInfo {
	vals := map[string]int{}
	inSection := false
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			inSection = strings.EqualFold(line, "[System Access]")
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !inSection || !ok {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			vals[strings.ToLower(strings.TrimSpace(k))] = n
		}
	}
	var p shared.PasswordPolicyInfo
	if n, ok := vals["minimumpasswordlength"]; ok {
		p.MinLength = shared.Int(n)
	}
	if n, ok := vals["passwordcomplexity"]; ok {
		p.Complexity = shared.Bool(n == 1)
	}
	if n, ok := vals["maximumpasswordage"]; ok {
		p.MaxAgeDays = shared.Int(max(n, 0))
	}
	if n, ok := vals["passwordhistorysize"]; ok {
		p.History = shared.Int(n)
	}
	if n, ok := vals["lockoutbadcount"]; ok {
		p.LockoutThreshold = shared.Int(n)
	}
	return nonZero(p)
}

// auditCategoryOf maps an advanced audit policy subcategory GUID to its
// category's English name. The GUIDs are fixed across Windows versions and
// languages ({0CCE92xx-69AE-11D9-BED3-505054503030}), which is why the
// collector reads `auditpol /backup` (GUIDs and numeric settings) rather
// than `auditpol /get`, whose text is localised.
func auditCategoryOf(guid string) string {
	g := strings.ToUpper(strings.Trim(strings.TrimSpace(guid), "{}"))
	if len(g) != 36 || !strings.HasPrefix(g, "0CCE") || !strings.HasSuffix(g, "-69AE-11D9-BED3-505054503030") {
		return ""
	}
	n, err := strconv.ParseUint(g[4:8], 16, 16)
	if err != nil {
		return ""
	}
	switch {
	case n >= 0x9210 && n <= 0x9214:
		return "System"
	case n >= 0x9215 && n <= 0x921C, n == 0x9243, n == 0x9247, n == 0x9249:
		return "Logon/Logoff"
	case n >= 0x921D && n <= 0x9227, n >= 0x9244 && n <= 0x9246:
		return "Object Access"
	case n >= 0x9228 && n <= 0x922A:
		return "Privilege Use"
	case n >= 0x922B && n <= 0x922E, n == 0x9248, n == 0x924A:
		return "Detailed Tracking"
	case n >= 0x922F && n <= 0x9234:
		return "Policy Change"
	case n >= 0x9235 && n <= 0x923A:
		return "Account Management"
	case n >= 0x923B && n <= 0x923E:
		return "DS Access"
	case n >= 0x923F && n <= 0x9242:
		return "Account Logon"
	}
	return ""
}

// parseAuditpolBackup reads the CSV written by `auditpol /backup`. Each
// subcategory row carries its GUID and a numeric "Setting Value" (0 none,
// 1 success, 2 failure, 3 both). Auditing counts as enabled when any
// subcategory audits something; categories lists those that do, sorted.
// ok is false when the file has no subcategory rows.
func parseAuditpolBackup(content string) (enabled bool, categories []string, ok bool) {
	r := csv.NewReader(strings.NewReader(content))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	header, err := r.Read()
	if err != nil {
		return false, nil, false
	}
	guidCol, valueCol := auditpolColumns(header)
	seen := map[string]bool{}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, nil, false
		}
		guid, value, isRow := auditpolSubcategory(rec, guidCol, valueCol)
		if !isRow {
			continue
		}
		ok = true
		if value <= 0 {
			continue
		}
		enabled = true
		if c := auditCategoryOf(guid); c != "" && !seen[c] {
			seen[c] = true
			categories = append(categories, c)
		}
	}
	sort.Strings(categories)
	return enabled, categories, ok
}

// auditpolColumns finds the GUID and setting-value columns in the header,
// defaulting to their standard positions.
func auditpolColumns(header []string) (guidCol, valueCol int) {
	guidCol, valueCol = 3, 6
	for i, h := range header {
		switch strings.ToLower(strings.TrimSpace(h)) {
		case "subcategory guid":
			guidCol = i
		case "setting value":
			valueCol = i
		}
	}
	return guidCol, valueCol
}

// auditpolSubcategory returns a subcategory row's GUID and numeric setting.
// isRow is false for option and global SACL rows, which have no GUID.
func auditpolSubcategory(rec []string, guidCol, valueCol int) (guid string, value int, isRow bool) {
	if guidCol >= len(rec) || valueCol >= len(rec) || strings.TrimSpace(rec[guidCol]) == "" {
		return "", 0, false
	}
	v, err := strconv.Atoi(strings.TrimSpace(rec[valueCol]))
	if err != nil {
		return "", 0, false
	}
	return rec[guidCol], v, true
}

// windowsEventLogMB is the Security event log's maximum size in MB. The
// Group Policy value (KB) wins over the service's own setting (bytes).
// Pass -1 for a value that isn't set.
func windowsEventLogMB(policyKB, serviceBytes int) *int {
	switch {
	case policyKB > 0:
		return shared.Int(policyKB / 1024)
	case serviceBytes > 0:
		return shared.Int(serviceBytes / (1024 * 1024))
	}
	return nil
}

// winSaverSettings is one signed-in user's screen saver configuration
// (HKU\<sid>\Control Panel\Desktop, overridden by the user's policy key).
type winSaverSettings struct {
	Active         bool
	Secure         bool
	TimeoutSeconds int
}

// windowsScreenLock combines the machine inactivity limit
// (InactivityTimeoutSecs, which always locks to the sign-in screen) with
// each signed-in user's password-protected screen saver. With several
// users, the weakest one is reported: the lock is only enabled when it is
// enabled for all of them, and the timeout is the longest. machineTimeout
// is -1 or 0 when the policy isn't set. Returns nil when there is neither a
// machine policy nor a signed-in user to read.
func windowsScreenLock(machineTimeout int, users []winSaverSettings) *shared.ScreenLockInfo {
	if machineTimeout <= 0 && len(users) == 0 {
		return nil
	}
	if len(users) == 0 {
		return &shared.ScreenLockInfo{
			Enabled:               shared.Bool(true),
			IdleTimeoutSeconds:    shared.Int(machineTimeout),
			RequirePasswordOnWake: shared.Bool(true),
		}
	}
	enabled, password, longest := true, true, 0
	for _, u := range users {
		timeout := max(machineTimeout, 0)
		if u.Active && u.Secure && u.TimeoutSeconds > 0 && (timeout == 0 || u.TimeoutSeconds < timeout) {
			timeout = u.TimeoutSeconds
		}
		if timeout == 0 {
			enabled = false
		}
		longest = max(longest, timeout)
		if machineTimeout <= 0 && !u.Secure {
			password = false
		}
	}
	info := &shared.ScreenLockInfo{Enabled: shared.Bool(enabled), RequirePasswordOnWake: shared.Bool(password)}
	if enabled {
		info.IdleTimeoutSeconds = shared.Int(longest)
	}
	return info
}

// windowsRDP derives RDP state from fDenyTSConnections and UserAuthentication
// (NLA). The Group Policy value of each wins over the local one. Pass -1 for
// a value that isn't set; a result is nil when neither value is set.
func windowsRDP(denyPolicy, deny, nlaPolicy, nla int) (enabled, nlaRequired *bool) {
	if d := firstSet(denyPolicy, deny); d >= 0 {
		enabled = shared.Bool(d == 0)
	}
	if n := firstSet(nlaPolicy, nla); n >= 0 {
		nlaRequired = shared.Bool(n == 1)
	}
	return enabled, nlaRequired
}

// firstSet returns the first value that is set (>= 0), or -1.
func firstSet(vals ...int) int {
	for _, v := range vals {
		if v >= 0 {
			return v
		}
	}
	return -1
}

// windowsAutoUpdate reports whether Windows Update installs updates on its
// own. Not when Group Policy sets NoAutoUpdate=1, when AUOptions leaves the
// install to the user (1 never check, 2 notify, 3 download and notify, 7
// notify to install and restart), or when the wuauserv service is disabled
// (Start=4). AUOptions 4 (scheduled install), 5 (local admin chooses) or
// unset leave Windows' automatic install on. Pass -1 for a value that isn't
// set. Unset policy values are normal (Windows' default applies), but an
// unreadable wuauserv service leaves the answer unknown (nil) unless policy
// already turns automatic install off.
func windowsAutoUpdate(noAutoUpdate, auOptions, wuauservStart int) *bool {
	switch auOptions {
	case 1, 2, 3, 7:
		return shared.Bool(false)
	}
	switch {
	case noAutoUpdate == 1 || wuauservStart == 4:
		return shared.Bool(false)
	case wuauservStart < 0:
		return nil
	}
	return shared.Bool(true)
}

// windowsBackupEnabled maps a backup agent's service Start value: automatic
// (0-2) is on, disabled (4) is off, and manual (3) is unknown.
func windowsBackupEnabled(start int) *bool {
	switch {
	case start >= 0 && start <= 2:
		return shared.Bool(true)
	case start == 4:
		return shared.Bool(false)
	}
	return nil
}

// windowsTimeSync builds time_sync from the W32Time Parameters Type and
// NtpServer values and the service's start type (-1 if unknown). Type
// NoSync, or a disabled service, means no synchronisation; a network sync
// Type (NTP, NT5DS, AllSync) on a service that isn't disabled means it's on.
// Otherwise (Type unread or unrecognised) Enabled is left out. Returns nil
// when nothing could be read.
func windowsTimeSync(syncType, ntpServer string, serviceStart int) *shared.TimeSyncInfo {
	t := strings.ToUpper(strings.TrimSpace(syncType))
	if t == "" && serviceStart < 0 {
		return nil
	}
	info := &shared.TimeSyncInfo{}
	switch {
	case t == "NOSYNC" || serviceStart == 4:
		info.Enabled = shared.Bool(false)
	case t == "NTP" || t == "NT5DS" || t == "ALLSYNC":
		info.Enabled = shared.Bool(true)
	}
	switch t {
	case "NTP", "ALLSYNC":
		// "time.windows.com,0x9 pool.ntp.org,0x1": first server, flags dropped.
		if fields := strings.Fields(ntpServer); len(fields) > 0 {
			info.Source, _, _ = strings.Cut(fields[0], ",")
		}
	case "NT5DS":
		info.Source = "domain hierarchy"
	}
	return info
}

// winComplianceProbe is the JSON object printed by the Windows compliance
// PowerShell script. A key the script couldn't read is absent (nil here).
// LastUpdate is Unix seconds.
type winComplianceProbe struct {
	GuestEnabled *bool  `json:"GuestEnabled"`
	SMB1         *bool  `json:"SMB1"`
	LastUpdate   *int64 `json:"LastUpdate"`
}

func parseWinComplianceProbe(output string) (winComplianceProbe, bool) {
	var p winComplianceProbe
	err := json.Unmarshal([]byte(strings.TrimSpace(output)), &p)
	return p, err == nil
}

// unixISOTime formats Unix seconds as ISO 8601 UTC, or "" for nil/<= 0.
func unixISOTime(sec *int64) string {
	if sec == nil || *sec <= 0 {
		return ""
	}
	return shared.ISOTime(time.Unix(*sec, 0))
}

// parseWindowsMissingUpdates reads the JSON array printed by the Windows
// Update search ({Id, Title, Critical} per update). critical counts Security
// and Critical updates, which feed the existing critical_kbs_missing field.
// ok is false when the output isn't the expected JSON, i.e. the search
// failed: the caller then leaves missing_updates out instead of claiming
// that nothing is missing.
func parseWindowsMissingUpdates(output string) (updates []shared.MissingUpdate, critical int, ok bool) {
	output = strings.TrimSpace(output)
	if !strings.HasPrefix(output, "[") && !strings.HasPrefix(output, "{") {
		return nil, 0, false
	}
	rows := decodePSObjects(output)
	if rows == nil && output != "[]" {
		return nil, 0, false
	}
	updates = []shared.MissingUpdate{}
	for _, row := range rows {
		id, _ := row["Id"].(string)
		title, _ := row["Title"].(string)
		if id == "" && title == "" {
			continue
		}
		if c, _ := row["Critical"].(bool); c {
			critical++
		}
		if len(updates) < maxMissingUpdates {
			updates = append(updates, shared.MissingUpdate{ID: id, Title: title})
		}
	}
	return updates, critical, true
}
