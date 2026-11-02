package mdm

// Windows logic that doesn't touch the registry, in a file without a build
// constraint so its tests run on every platform.

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

// Ineligibility reasons for Windows MDM enrollment.
const (
	ReasonHomeEdition   = "home_edition"
	ReasonServer        = "server"
	ReasonPolicyBlocked = "policy_blocked"
)

// winEnrollment is one key under HKLM\SOFTWARE\Microsoft\Enrollments.
type winEnrollment struct {
	id           string
	providerID   string
	discoveryURL string
	upn          string
	typ          uint64
	state        uint64
}

// winPolicy is one effective policy under PolicyManager\current\device:
// its area, name and the GUID of the enrollment that set it.
type winPolicy struct {
	area, name, winningProvider string
}

// winFacts is what the Windows collector reads.
type winFacts struct {
	policies         []winPolicy
	editionID        string // e.g. Professional, Enterprise, Core (Home), ServerStandard
	installationType string // Client, Server, Server Core
	allowed          *bool  // IsManagementRegistrationAllowed
	registered       *bool  // IsDeviceRegisteredWithManagement
	enrollments      []winEnrollment
	omadmDeviceID    string
	smbiosUUID       string
}

// isMDMEnrollment tells real MDM enrollments from the many other entries
// Windows keeps under Enrollments (provisioning, "Local Authority", "Deploy
// Authority" and others, present on every PC): an active MDM enrollment has
// a discovery service URL.
func isMDMEnrollment(e winEnrollment) bool {
	return e.state == 1 && strings.TrimSpace(e.discoveryURL) != ""
}

// enrollmentType names an EnrollmentType value.
func enrollmentType(t uint64) string {
	switch t {
	case 6:
		return "mdm_only" // enrolled in device management only (Settings, or the agent)
	case 13:
		return "entra_auto" // Entra join with automatic MDM enrollment
	default:
		return "other:" + strconv.FormatUint(t, 10)
	}
}

func enrollmentState(s uint64) string {
	if s == 1 {
		return "enrolled"
	}
	return "state:" + strconv.FormatUint(s, 10)
}

// normalizeUUID turns "{65474863-FE40-...}" into "65474863-fe40-...".
func normalizeUUID(s string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(s), "{}"))
}

// buildWindowsInfo combines the collected facts into the reported block.
func buildWindowsInfo(f winFacts, ourHost string, now time.Time) *shared.MDMInfo {
	info := &shared.MDMInfo{
		EnrollmentType: TypeNone,
		Edition:        f.editionID,
		Identity:       shared.MDMIdentity{OMADMDeviceID: strings.TrimSpace(f.omadmDeviceID), SMBIOSUUID: normalizeUUID(f.smbiosUUID)},
		CollectedAt:    now.UTC(),
	}

	edition, install := strings.ToLower(f.editionID), strings.ToLower(f.installationType)
	switch {
	case strings.HasPrefix(install, "server") || strings.HasPrefix(edition, "server"):
		info.IneligibleReason = ReasonServer
	case strings.HasPrefix(edition, "core"): // Home: Core, CoreN, CoreSingleLanguage, CoreCountrySpecific
		info.IneligibleReason = ReasonHomeEdition
	case f.allowed != nil && !*f.allowed:
		info.IneligibleReason = ReasonPolicyBlocked
	}
	info.Eligible = boolPtr(info.IneligibleReason == "")

	var mdmEnrollments []winEnrollment
	for _, e := range f.enrollments {
		if !isMDMEnrollment(e) {
			continue
		}
		mdmEnrollments = append(mdmEnrollments, e)
		info.Enrollments = append(info.Enrollments, shared.MDMEnrollment{
			ID: e.id, ProviderID: e.providerID, ServerHost: hostOf(e.discoveryURL),
			Type: enrollmentType(e.typ), State: enrollmentState(e.state), UPN: e.upn,
		})
	}
	info.Enrolled = len(mdmEnrollments) > 0 || (f.registered != nil && *f.registered)
	info.MDMPolicyAreas, info.ManagedSettings = mdmManaged(f.policies, mdmEnrollments)
	if !info.Enrolled {
		return info
	}

	info.EnrollmentType = TypeUnknown
	for i, e := range info.Enrollments {
		if isOurServer(e.ServerHost, ourHost) {
			info.IsOurServer, info.ServerURLHost, info.EnrollmentType = true, e.ServerHost, enrollmentType(mdmEnrollments[i].typ)
			return info
		}
	}
	if len(info.Enrollments) > 0 {
		first := info.Enrollments[0]
		info.ServerURLHost, info.EnrollmentType = first.ServerHost, enrollmentType(mdmEnrollments[0].typ)
		if strings.TrimSpace(ourHost) != "" {
			info.OtherMDM = first.ServerHost
			if info.OtherMDM == "" {
				info.OtherMDM = first.ProviderID
			}
		}
	}
	return info
}

// settingsByArea maps a Policy CSP area to the console setting it covers.
var settingsByArea = map[string]string{
	"autoplay":                     "autoplay",
	"devicelock":                   "screen_lock",
	"localpoliciessecurityoptions": "screen_lock", // InteractiveLogon_MachineInactivityLimit
	"storage":                      "removable_media",
	"deviceinstallation":           "removable_media",
	"defender":                     "defender",
	"update":                       "software_update",
	"bitlocker":                    "bitlocker",
}

// mdmManaged returns the policy areas, and the settings they cover, where
// the effective policy was set by one of the MDM enrollments. Policies set
// by provisioning or local providers (present on every PC) don't count.
func mdmManaged(policies []winPolicy, mdmEnrollments []winEnrollment) (areas, settings []string) {
	ids := map[string]bool{}
	for _, e := range mdmEnrollments {
		ids[strings.ToLower(strings.Trim(e.id, "{}"))] = true
	}
	if len(ids) == 0 {
		return nil, nil
	}
	for _, p := range policies {
		if !ids[strings.ToLower(strings.Trim(p.winningProvider, "{}"))] {
			continue
		}
		if !slices.Contains(areas, p.area) {
			areas = append(areas, p.area)
		}
		if s, ok := settingsByArea[strings.ToLower(p.area)]; ok && !slices.Contains(settings, s) {
			settings = append(settings, s)
		}
	}
	slices.Sort(areas)
	slices.Sort(settings)
	return areas, settings
}
