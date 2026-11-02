package mdm

// Parsers for the macOS tools the darwin collector runs. They're in a file
// without a build constraint so their tests run on every platform.

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

// enrollmentStatus is what `profiles status -type enrollment` reports.
type enrollmentStatus struct {
	known        bool // the "MDM enrollment" line was there
	enrolled     bool
	userApproved bool
	viaDEP       bool
	serverURL    string
}

// parseEnrollmentStatus parses `profiles status -type enrollment`:
//
//	Enrolled via DEP: Yes
//	MDM enrollment: Yes (User Approved)
//	MDM server: https://mdm.example.com/mdm/connect
//
// The server line is printed on macOS 13 and later. The value is split at
// the first colon, since the server URL has colons of its own.
func parseEnrollmentStatus(out string) enrollmentStatus {
	var st enrollmentStatus
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimPrefix(strings.TrimSpace(line), "profiles: ")
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		yes := strings.HasPrefix(strings.ToLower(value), "yes")
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "enrolled via dep":
			st.viaDEP = yes
		case "mdm enrollment":
			st.known = true
			st.enrolled = yes
			st.userApproved = strings.Contains(strings.ToLower(value), "user approved")
		case "mdm server":
			st.serverURL = value
		}
	}
	return st
}

// adeConfig is what `profiles show -type enrollment` reports: whether Apple
// Business Manager assigns the Mac to an MDM server, and which one.
type adeConfig struct {
	assigned  *bool // nil when it couldn't be determined
	serverURL string
}

var configurationURL = regexp.MustCompile(`ConfigurationURL\s*=\s*"?([^";\s]+)`)

// parseADEConfig parses `profiles show -type enrollment`. An assigned Mac
// prints its "Device Enrollment configuration" dictionary with a
// ConfigurationURL; an unassigned one reports "Client is not DEP enabled".
// Anything else (no network, Apple's servers unreachable) is unknown.
func parseADEConfig(out string) adeConfig {
	if m := configurationURL.FindStringSubmatch(out); m != nil {
		return adeConfig{assigned: boolPtr(true), serverURL: m[1]}
	}
	if strings.Contains(strings.ToLower(out), "not dep enabled") {
		return adeConfig{assigned: boolPtr(false)}
	}
	return adeConfig{}
}

// parseBootstrapToken parses `profiles status -type bootstraptoken`, e.g.
// "profiles: Bootstrap Token escrowed to server: YES". nil when the line
// isn't there (older macOS, or the command failed).
func parseBootstrapToken(out string) *bool {
	for _, line := range strings.Split(out, "\n") {
		i := strings.LastIndex(line, ":")
		if i < 0 || !strings.Contains(strings.ToLower(line[:i]), "escrowed") {
			continue
		}
		return boolPtr(strings.EqualFold(strings.TrimSpace(line[i+1:]), "yes"))
	}
	return nil
}

// parseHardwareIdentity reads `system_profiler SPHardwareDataType -json`.
// The provisioning UDID is what Apple MDM identifies a Mac by; on Apple
// silicon it differs from the hardware (platform) UUID. Intel Macs and older
// macOS don't report it, and there the MDM UDID is the hardware UUID.
func parseHardwareIdentity(out string) shared.MDMIdentity {
	var doc struct {
		Hardware []struct {
			Serial           string `json:"serial_number"`
			PlatformUUID     string `json:"platform_UUID"`
			ProvisioningUDID string `json:"provisioning_UDID"`
		} `json:"SPHardwareDataType"`
	}
	if json.Unmarshal([]byte(out), &doc) != nil || len(doc.Hardware) == 0 {
		return shared.MDMIdentity{}
	}
	h := doc.Hardware[0]
	id := shared.MDMIdentity{
		Serial:           strings.TrimSpace(h.Serial),
		HardwareUUID:     strings.TrimSpace(h.PlatformUUID),
		ProvisioningUDID: strings.TrimSpace(h.ProvisioningUDID),
	}
	if id.ProvisioningUDID == "" {
		id.ProvisioningUDID = id.HardwareUUID
	}
	return id
}

// buildMacInfo combines the parsed outputs into the reported block.
func buildMacInfo(st enrollmentStatus, ade adeConfig, bootstrap *bool, id shared.MDMIdentity, ourHost string, now time.Time) *shared.MDMInfo {
	info := &shared.MDMInfo{
		Enrolled:               st.enrolled,
		UserApproved:           st.userApproved,
		EnrollmentType:         TypeUnknown,
		ServerURLHost:          hostOf(st.serverURL),
		ADEAssigned:            ade.assigned,
		ADEServerHost:          hostOf(ade.serverURL),
		BootstrapTokenEscrowed: bootstrap,
		Identity:               id,
		CollectedAt:            now.UTC(),
	}
	info.IsOurServer = isOurServer(info.ServerURLHost, ourHost)
	if !st.known {
		return info // enrollment state unknown: leave supervision unknown too
	}
	switch {
	case st.enrolled && st.viaDEP:
		// Macs enrolled through ADE are supervised (macOS 11 and later).
		info.EnrollmentType, info.Supervised = TypeADE, boolPtr(true)
		info.ADEAssigned = boolPtr(true)
	case st.enrolled:
		// A profile the user installed never makes a Mac supervised.
		info.EnrollmentType, info.Supervised = TypeProfile, boolPtr(false)
	default:
		info.EnrollmentType, info.Supervised = TypeNone, boolPtr(false)
	}
	return info
}
