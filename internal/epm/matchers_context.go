package epm

import (
	"runtime"
	"strconv"
	"strings"
	"time"
)

// This file implements every Matcher sourced from EvalInput.Context
// (ContextSnapshot) or computed inline from EvalInput.Now/Defaults — device
// posture, network, org/directory, and time. See matchers_identity.go for the
// request-sourced matchers and allBuiltinMatchers, which assembles both sets
// into the registry DefaultMatchers returns.
//
// Every matcher here that reads ContextSnapshot checks sourceFresh first: with
// no ContextProvider wired (epm_context_mode=off, or simply Phase 4 not built
// yet), Sources is nil, sourceFresh always returns false, and every one of
// these conditions is Unknown — which is exactly today's behavior, since no
// v1 rule uses any of them.

// sourceFresh reports whether ctx.Sources[key] exists, succeeded, and is not
// older than maxAge (0 meaning "never stale" once present).
func sourceFresh(ctx *ContextSnapshot, key string, maxAge time.Duration, now time.Time) bool {
	if ctx.Sources == nil {
		return false
	}
	state, ok := ctx.Sources[key]
	if !ok || !state.OK {
		return false
	}
	if maxAge <= 0 {
		return true
	}
	return now.Sub(state.CollectedAt) <= maxAge
}

// contextPostureMaxAge/contextNetworkMaxAge match the slow/medium collection
// cadences Phase 4 documents (15 min / 60 s), doubled per the "stale beyond
// 2x the refresh interval" rule stated in the plan: a wedged collector should
// degrade to Unknown well before its data becomes actively misleading, but
// not flap Unknown on every ordinary collection jitter.
const (
	contextPostureMaxAge = 30 * time.Minute
	contextNetworkMaxAge = 2 * time.Minute
	contextJoinMaxAge    = 30 * time.Minute
)

// --- Directory / organization ---

type deviceGroupMatcher struct{}

func (deviceGroupMatcher) Kind() ConditionKind   { return CondDeviceGroup }
func (deviceGroupMatcher) Weight() int           { return WeightOrgUnit }
func (deviceGroupMatcher) MaxAge() time.Duration { return contextPostureMaxAge }
func (deviceGroupMatcher) Extract(in *EvalInput) ([]string, bool) {
	if len(in.Context.DeviceGroups) == 0 {
		return nil, false
	}
	return in.Context.DeviceGroups, true
}

type orgMatcher struct{}

func (orgMatcher) Kind() ConditionKind   { return CondOrg }
func (orgMatcher) Weight() int           { return WeightOrgUnit }
func (orgMatcher) MaxAge() time.Duration { return contextPostureMaxAge }
func (orgMatcher) Extract(in *EvalInput) ([]string, bool) {
	if in.Context.Org == "" {
		return nil, false
	}
	return []string{in.Context.Org}, true
}

type departmentMatcher struct{}

func (departmentMatcher) Kind() ConditionKind   { return CondDepartment }
func (departmentMatcher) Weight() int           { return WeightOrgUnit }
func (departmentMatcher) MaxAge() time.Duration { return contextPostureMaxAge }
func (departmentMatcher) Extract(in *EvalInput) ([]string, bool) {
	if in.Context.Department == "" {
		return nil, false
	}
	return []string{in.Context.Department}, true
}

type domainJoinedMatcher struct{}

func (domainJoinedMatcher) Kind() ConditionKind   { return CondDomainJoined }
func (domainJoinedMatcher) Weight() int           { return WeightOrgUnit }
func (domainJoinedMatcher) MaxAge() time.Duration { return contextJoinMaxAge }
func (domainJoinedMatcher) Extract(in *EvalInput) ([]string, bool) {
	if !sourceFresh(&in.Context, "join", contextJoinMaxAge, in.Now) {
		return nil, false
	}
	if in.Context.DomainJoined == TriUnknown {
		return nil, false
	}
	return []string{strconv.FormatBool(in.Context.DomainJoined == TriTrue)}, true
}

type entraJoinedMatcher struct{}

func (entraJoinedMatcher) Kind() ConditionKind   { return CondEntraJoined }
func (entraJoinedMatcher) Weight() int           { return WeightOrgUnit }
func (entraJoinedMatcher) MaxAge() time.Duration { return contextJoinMaxAge }
func (entraJoinedMatcher) Extract(in *EvalInput) ([]string, bool) {
	if !sourceFresh(&in.Context, "join", contextJoinMaxAge, in.Now) {
		return nil, false
	}
	if in.Context.EntraJoined == TriUnknown {
		return nil, false
	}
	return []string{strconv.FormatBool(in.Context.EntraJoined == TriTrue)}, true
}

// --- Device posture ---

// posturalStringMatcher is the shared shape for the five posture fields that
// are plain descriptive strings ("enabled"/"disabled"/"unknown"/…) rather
// than Tri: the value "unknown" reported BY THE COLLECTOR is itself treated
// as Unknown here (not as a literal string to match against), since a rule
// author writing disk_encryption=unknown to mean something is a
// misunderstanding this Extract deliberately forecloses.
func posturalValue(ctx *ContextSnapshot, key, value string, maxAge time.Duration, now time.Time) ([]string, bool) {
	if !sourceFresh(ctx, key, maxAge, now) {
		return nil, false
	}
	if value == "" || value == "unknown" {
		return nil, false
	}
	return []string{value}, true
}

type diskEncryptionMatcher struct{}

func (diskEncryptionMatcher) Kind() ConditionKind   { return CondDiskEncryption }
func (diskEncryptionMatcher) Weight() int           { return WeightPosture }
func (diskEncryptionMatcher) MaxAge() time.Duration { return contextPostureMaxAge }
func (diskEncryptionMatcher) Extract(in *EvalInput) ([]string, bool) {
	return posturalValue(&in.Context, "posture", in.Context.DiskEncryption, contextPostureMaxAge, in.Now)
}

type secureBootMatcher struct{}

func (secureBootMatcher) Kind() ConditionKind   { return CondSecureBoot }
func (secureBootMatcher) Weight() int           { return WeightPosture }
func (secureBootMatcher) MaxAge() time.Duration { return contextPostureMaxAge }
func (secureBootMatcher) Extract(in *EvalInput) ([]string, bool) {
	return posturalValue(&in.Context, "posture", in.Context.SecureBoot, contextPostureMaxAge, in.Now)
}

type firewallMatcher struct{}

func (firewallMatcher) Kind() ConditionKind   { return CondFirewall }
func (firewallMatcher) Weight() int           { return WeightPosture }
func (firewallMatcher) MaxAge() time.Duration { return contextPostureMaxAge }
func (firewallMatcher) Extract(in *EvalInput) ([]string, bool) {
	return posturalValue(&in.Context, "posture", in.Context.FirewallState, contextPostureMaxAge, in.Now)
}

type antivirusMatcher struct{}

func (antivirusMatcher) Kind() ConditionKind   { return CondAntivirus }
func (antivirusMatcher) Weight() int           { return WeightPosture }
func (antivirusMatcher) MaxAge() time.Duration { return contextPostureMaxAge }
func (antivirusMatcher) Extract(in *EvalInput) ([]string, bool) {
	return posturalValue(&in.Context, "posture", in.Context.AntivirusHealth, contextPostureMaxAge, in.Now)
}

type complianceMatcher struct{}

func (complianceMatcher) Kind() ConditionKind   { return CondCompliance }
func (complianceMatcher) Weight() int           { return WeightPosture }
func (complianceMatcher) MaxAge() time.Duration { return contextPostureMaxAge }
func (complianceMatcher) Extract(in *EvalInput) ([]string, bool) {
	return posturalValue(&in.Context, "posture", in.Context.Compliance, contextPostureMaxAge, in.Now)
}

// --- Network ---

type networkTypeMatcher struct{}

func (networkTypeMatcher) Kind() ConditionKind   { return CondNetworkType }
func (networkTypeMatcher) Weight() int           { return WeightPosture }
func (networkTypeMatcher) MaxAge() time.Duration { return contextNetworkMaxAge }
func (networkTypeMatcher) Extract(in *EvalInput) ([]string, bool) {
	return posturalValue(&in.Context, "network", in.Context.NetworkType, contextNetworkMaxAge, in.Now)
}

type vpnActiveMatcher struct{}

func (vpnActiveMatcher) Kind() ConditionKind   { return CondVPNActive }
func (vpnActiveMatcher) Weight() int           { return WeightPosture }
func (vpnActiveMatcher) MaxAge() time.Duration { return contextNetworkMaxAge }
func (vpnActiveMatcher) Extract(in *EvalInput) ([]string, bool) {
	if !sourceFresh(&in.Context, "network", contextNetworkMaxAge, in.Now) {
		return nil, false
	}
	if in.Context.VPNActive == TriUnknown {
		return nil, false
	}
	return []string{strconv.FormatBool(in.Context.VPNActive == TriTrue)}, true
}

type corporateNetworkMatcher struct{}

func (corporateNetworkMatcher) Kind() ConditionKind   { return CondCorporateNetwork }
func (corporateNetworkMatcher) Weight() int           { return WeightPosture }
func (corporateNetworkMatcher) MaxAge() time.Duration { return contextNetworkMaxAge }
func (corporateNetworkMatcher) Extract(in *EvalInput) ([]string, bool) {
	if !sourceFresh(&in.Context, "network", contextNetworkMaxAge, in.Now) {
		return nil, false
	}
	if in.Context.CorporateNetwork == TriUnknown {
		return nil, false
	}
	return []string{strconv.FormatBool(in.Context.CorporateNetwork == TriTrue)}, true
}

// --- Time ---

var weekdayAbbrev = [...]string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}

// resolveTimeLocation resolves the IANA zone a time.Time condition should
// evaluate in: the leaf's own Timezone, else Defaults.Timezone, else the
// device's local zone. An unrecognised zone name falls back to local rather
// than failing the whole evaluation over a config typo.
func resolveTimeLocation(leafTZ, defaultTZ string) *time.Location {
	name := leafTZ
	if name == "" {
		name = defaultTZ
	}
	if name == "" {
		return time.Local
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return time.Local
	}
	return loc
}

// businessHoursMatcher is computed inline from Now — never Unknown, because
// "no business-hours policy is configured" is itself a known fact (the
// condition simply does not match), not a missing one. See CondBusinessHours.
type businessHoursMatcher struct{}

func (businessHoursMatcher) Kind() ConditionKind   { return CondBusinessHours }
func (businessHoursMatcher) Weight() int           { return WeightPosture }
func (businessHoursMatcher) MaxAge() time.Duration { return 0 }
func (businessHoursMatcher) Extract(in *EvalInput) ([]string, bool) {
	if in.Defaults.BusinessHoursStart == "" || in.Defaults.BusinessHoursEnd == "" {
		return nil, false
	}
	loc := resolveTimeLocation("", in.Defaults.Timezone)
	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	local := now.In(loc)

	if len(in.Defaults.BusinessDays) > 0 {
		today := weekdayAbbrev[int(local.Weekday())]
		dayOK := false
		for _, d := range in.Defaults.BusinessDays {
			if strings.EqualFold(d, today) {
				dayOK = true
				break
			}
		}
		if !dayOK {
			return []string{"false"}, true
		}
	}

	cur := local.Format("15:04")
	inWindow := cur >= in.Defaults.BusinessHoursStart && cur <= in.Defaults.BusinessHoursEnd
	return []string{strconv.FormatBool(inWindow)}, true
}

// dayOfWeekMatcher is likewise always known: the current weekday is always
// computable from Now with no external collector.
type dayOfWeekMatcher struct{}

func (dayOfWeekMatcher) Kind() ConditionKind   { return CondDayOfWeek }
func (dayOfWeekMatcher) Weight() int           { return WeightPosture }
func (dayOfWeekMatcher) MaxAge() time.Duration { return 0 }
func (dayOfWeekMatcher) Extract(in *EvalInput) ([]string, bool) {
	loc := resolveTimeLocation("", in.Defaults.Timezone)
	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return []string{weekdayAbbrev[int(now.In(loc).Weekday())]}, true
}

// --- Platform ---

// osTypeMatcher is always known: runtime.GOOS needs no collector at all.
type osTypeMatcher struct{}

func (osTypeMatcher) Kind() ConditionKind   { return CondOSType }
func (osTypeMatcher) Weight() int           { return WeightPosture }
func (osTypeMatcher) MaxAge() time.Duration { return 0 }
func (osTypeMatcher) Extract(*EvalInput) ([]string, bool) {
	return []string{runtime.GOOS}, true
}

type osVersionMatcher struct{}

func (osVersionMatcher) Kind() ConditionKind   { return CondOSVersion }
func (osVersionMatcher) Weight() int           { return WeightPosture }
func (osVersionMatcher) MaxAge() time.Duration { return contextPostureMaxAge }
func (osVersionMatcher) Extract(in *EvalInput) ([]string, bool) {
	if !sourceFresh(&in.Context, "posture", contextPostureMaxAge, in.Now) {
		return nil, false
	}
	if in.Context.OSVersion == "" {
		return nil, false
	}
	return []string{in.Context.OSVersion}, true
}
