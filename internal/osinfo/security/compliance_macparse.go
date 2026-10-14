package security

// macOS compliance parsers. No OS suffix so they are tested everywhere;
// compliance_darwin.go calls them.

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

// ── password policy ───────────────────────────────────────────────────────────

var pwpolicyMinLenRe = regexp.MustCompile(`\.\{(\d+),`)

// pwpolicyClassRe matches policyContent regexes that require a character
// class: digits, letters, upper/lower case, or symbols.
var pwpolicyClassRe = map[string]*regexp.Regexp{
	"numeric": regexp.MustCompile(`\[0-9\]|\\d`),
	"alpha":   regexp.MustCompile(`\[a-zA-Z\]|\[A-Za-z\]`),
	"upper":   regexp.MustCompile(`\[A-Z\]`),
	"lower":   regexp.MustCompile(`\[a-z\]`),
	"symbol":  regexp.MustCompile(`\[\^a-zA-Z0-9\]|\[\^A-Za-z0-9\]`),
}

// pwpolicyClassParams are policyParameters that require a character class.
var pwpolicyClassParams = map[string]string{
	"minimumNumericCharacters":   "numeric",
	"minimumAlphaCharacters":     "alpha",
	"minimumMixedCaseCharacters": "upper",
	"minimumSymbols":             "symbol",
	"minComplexChars":            "symbol",
}

// macPasswordPolicy reads `pwpolicy -getaccountpolicies`, a plist of policy
// dicts grouped by category, each with a policyContent predicate and
// policyParameters. Output without a plist (no policy at all) means nothing
// is enforced, which is reported as zeros. Complexity means at least two
// character classes are required. Nil when the output can't be parsed.
func macPasswordPolicy(output string) *shared.PasswordPolicyInfo {
	zero := shared.PasswordPolicyInfo{
		MinLength: shared.Int(0), Complexity: shared.Bool(false), MaxAgeDays: shared.Int(0),
		History: shared.Int(0), LockoutThreshold: shared.Int(0),
	}
	if !strings.Contains(output, "<plist") {
		if strings.Contains(strings.ToLower(output), "no global policies") || strings.TrimSpace(output) == "" {
			return &zero
		}
		return nil
	}
	root, ok := shared.PlistFromOutput(output)
	if !ok {
		return nil
	}
	// Every policy applies at once, so where several set the same limit the
	// strictest wins: the longest minimum length and history, the shortest
	// maximum age and lockout threshold. That also keeps the result
	// independent of the (unordered) category map.
	var minLen, history, maxAge, lockout int
	classes := map[string]bool{}
	for _, policy := range pwpolicyEntries(root) {
		content, _ := policy["policyContent"].(string)
		params, _ := policy["policyParameters"].(map[string]any)
		minLen = max(minLen, pwpolicyMinLength(content, params))
		history = max(history, pwpolicyParam(params, "policyAttributePasswordHistoryDepth"))
		maxAge = minPositive(maxAge, pwpolicyMaxAgeDays(params))
		lockout = minPositive(lockout, pwpolicyParam(params, "policyAttributeMaximumFailedAuthentications", "maxFailedAttempts"))
		addPwpolicyClasses(classes, content, params)
	}
	return &shared.PasswordPolicyInfo{
		MinLength:        shared.Int(minLen),
		Complexity:       shared.Bool(len(classes) >= 2),
		MaxAgeDays:       shared.Int(maxAge),
		History:          shared.Int(history),
		LockoutThreshold: shared.Int(lockout),
	}
}

// minPositive returns the smaller of a and b, ignoring zeros (0 = no limit).
func minPositive(a, b int) int {
	switch {
	case a <= 0:
		return max(b, 0)
	case b <= 0:
		return a
	}
	return min(a, b)
}

// pwpolicyEntries flattens the policy dicts of every category.
func pwpolicyEntries(root any) []map[string]any {
	dict, _ := root.(map[string]any)
	var out []map[string]any
	for _, v := range dict {
		list, _ := v.([]any)
		for _, item := range list {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

// pwpolicyParam returns the first of the named policyParameters as an int,
// or 0 when none is set or the value is out of range.
func pwpolicyParam(params map[string]any, names ...string) int {
	for _, n := range names {
		if _, ok := shared.PlistNumber(params[n]); ok {
			v, _ := shared.PlistInt(params[n])
			return v
		}
	}
	return 0
}

// pwpolicyMinLength reads a minimum length from the minimumLength parameter,
// else from a "policyAttributePassword matches '.{N,}+'" predicate.
func pwpolicyMinLength(content string, params map[string]any) int {
	if n := pwpolicyParam(params, "minimumLength", "minLength"); n > 0 {
		return n
	}
	if !strings.Contains(content, "policyAttributePassword matches") {
		return 0
	}
	if m := pwpolicyMinLenRe.FindStringSubmatch(content); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

// pwpolicyMaxAgeDays reads the password expiry in days (or in minutes, from
// MDM's maxMinutesUntilChangePassword).
func pwpolicyMaxAgeDays(params map[string]any) int {
	if n := pwpolicyParam(params, "policyAttributeExpiresEveryNDays"); n > 0 {
		return n
	}
	return pwpolicyParam(params, "maxMinutesUntilChangePassword") / (60 * 24)
}

// addPwpolicyClasses records the character classes a policy requires.
func addPwpolicyClasses(classes map[string]bool, content string, params map[string]any) {
	for name, class := range pwpolicyClassParams {
		if pwpolicyParam(params, name) > 0 {
			classes[class] = true
		}
	}
	if !strings.Contains(content, "policyAttributePassword matches") {
		return
	}
	for class, re := range pwpolicyClassRe {
		if re.MatchString(content) {
			classes[class] = true
		}
	}
}

// ── screen lock ───────────────────────────────────────────────────────────────

var (
	screenLockDelayRe   = regexp.MustCompile(`screenLock delay is (\d+) seconds?`)
	pmsetDisplaySleepRe = regexp.MustCompile(`(?m)^\s*displaysleep\s+(\d+)`)
)

// parseSysadminctlScreenLock reads `sysadminctl -screenLock status` (logged
// to stderr): "screenLock delay is immediate", "screenLock delay is 5
// seconds" or "screenLock is off". delay is the grace period after the
// screen saver starts or the display sleeps before a password is needed.
func parseSysadminctlScreenLock(output string) (required bool, delaySeconds int, ok bool) {
	switch {
	case strings.Contains(output, "screenLock delay is immediate"):
		return true, 0, true
	case strings.Contains(output, "screenLock is off"):
		return false, 0, true
	}
	if m := screenLockDelayRe.FindStringSubmatch(output); m != nil {
		n, err := strconv.Atoi(m[1])
		return err == nil, n, err == nil
	}
	return false, 0, false
}

// parsePmsetDisplaySleep reads the displaysleep minutes from `pmset -g`
// (0 = never).
func parsePmsetDisplaySleep(output string) (minutes int, ok bool) {
	m := pmsetDisplaySleepRe.FindStringSubmatch(output)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

// macScreenLock combines the screen saver idle time (seconds, 0 = never,
// -1 unknown), the display sleep (minutes, 0 = never, -1 unknown) and the
// password requirement (nil unknown) with its delay (seconds, -1 unknown).
// The screen locks after whichever of screen saver and display sleep comes
// first, plus the delay.
//
// Enabled is only reported false on firm evidence: no password is required,
// or both idle sources are known to be off. One source off and the other
// unread could still lock, so Enabled is left out then. The timeout is left
// out when the delay or either idle source is unknown, since the unread
// source could lock sooner.
func macScreenLock(saverIdle, displaySleepMin int, password *bool, delaySeconds int) *shared.ScreenLockInfo {
	idleKnown := saverIdle >= 0 || displaySleepMin >= 0
	if password == nil && !idleKnown {
		return nil
	}
	idle := minPositive(saverIdle, displaySleepMin*60)
	neverIdle := saverIdle == 0 && displaySleepMin == 0
	info := &shared.ScreenLockInfo{RequirePasswordOnWake: password}
	switch {
	case password != nil && !*password:
		info.Enabled = shared.Bool(false)
	case neverIdle:
		info.Enabled = shared.Bool(false)
	case password != nil && idle > 0:
		info.Enabled = shared.Bool(true)
	}
	if idle > 0 && saverIdle >= 0 && displaySleepMin >= 0 && (password == nil || *password) && delaySeconds >= 0 {
		info.IdleTimeoutSeconds = shared.Int(idle + delaySeconds)
	}
	return info
}

// ── patching ──────────────────────────────────────────────────────────────────

// macSystemUpdateProcesses are the InstallHistory processName values of OS
// updates and upgrades (App Store and user-installed packages are ignored).
var macSystemUpdateProcesses = map[string]bool{
	"softwareupdated": true, "Software Update": true, "macOS Installer": true, "OS X Installer": true,
}

// macBackgroundUpdate matches the security data files softwareupdated
// installs silently every few days (XProtect, MRT, Gatekeeper). They aren't
// OS patches and would make every Mac look freshly patched.
var macBackgroundUpdate = regexp.MustCompile(`(?i)ConfigData|XProtect|Gatekeeper|MRT`)

// macLastUpdate reads /Library/Receipts/InstallHistory.plist (an array of
// {date, displayName, processName}) and returns the latest OS update.
func macLastUpdate(root any) (time.Time, bool) {
	list, _ := root.([]any)
	var last time.Time
	for _, item := range list {
		m, _ := item.(map[string]any)
		proc, _ := m["processName"].(string)
		name, _ := m["displayName"].(string)
		date, _ := m["date"].(time.Time)
		if macSystemUpdateProcesses[proc] && !macBackgroundUpdate.MatchString(name) && date.After(last) {
			last = date
		}
	}
	return last, !last.IsZero()
}

// macAutoUpdate reads com.apple.SoftwareUpdate (managed values merged over
// local ones by the caller). Updates count as automatic only when the Mac
// checks for updates, installs security responses and system files, and
// installs macOS updates, all by itself. The first two default to on when
// unset; installing macOS updates defaults to off.
func macAutoUpdate(prefs map[string]any) bool {
	on := func(key string, def bool) bool {
		if b, ok := shared.PlistBool(prefs[key]); ok {
			return b
		}
		return def
	}
	return on("AutomaticCheckEnabled", true) && on("CriticalUpdateInstall", true) &&
		on("AutomaticallyInstallMacOSUpdates", false)
}

// ── audit / time / backup ─────────────────────────────────────────────────────

// parseAuditControl reads the "flags:" line of /etc/security/audit_control,
// the audit classes recorded for every user (e.g. "lo,aa").
func parseAuditControl(content string) (flags []string, ok bool) {
	for _, line := range strings.Split(content, "\n") {
		v, found := strings.CutPrefix(strings.TrimSpace(line), "flags:")
		if !found {
			continue
		}
		for _, f := range strings.Split(v, ",") {
			if f = strings.TrimSpace(f); f != "" {
				flags = append(flags, f)
			}
		}
		return flags, true
	}
	return nil, false
}

// colonValue returns the text after the first ": " in a systemsetup line
// such as "Network Time: On".
func colonValue(output string) string {
	_, v, _ := strings.Cut(strings.TrimSpace(output), ":")
	return strings.TrimSpace(v)
}

var tmBackupStampRe = regexp.MustCompile(`(\d{4}-\d{2}-\d{2}-\d{6})`)

// parseTimeMachineLatest reads the path printed by `tmutil latestbackup`,
// whose last element is the backup's local time
// (".../2026-10-14-010000.backup" or ".../2026-10-14-010000").
func parseTimeMachineLatest(output string, loc *time.Location) (time.Time, bool) {
	m := tmBackupStampRe.FindAllString(output, -1)
	if m == nil {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation("2006-01-02-150405", m[len(m)-1], loc)
	return t, err == nil
}

// tmHasDestination reads `tmutil destinationinfo`.
func tmHasDestination(output string) bool {
	return strings.Contains(output, "Name") && !strings.Contains(output, "No destinations configured")
}
