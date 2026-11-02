// Package mdm reports a device's MDM enrollment state and the identifiers
// an MDM server knows it by (contract v1 "mdm" block, #348). The agent never
// speaks an MDM protocol itself: the OS's own MDM client does. This package
// only reads what that client and the OS report.
package mdm

import (
	"net/url"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// Enrollment types reported in MDMInfo.EnrollmentType.
const (
	TypeADE     = "ade"     // Automated Device Enrollment (Apple Business Manager)
	TypeProfile = "profile" // an enrollment profile installed on the device
	TypeNone    = "none"
	TypeUnknown = "unknown"
)

// Collect returns the device's MDM state, or nil on platforms without a
// collector. ourHost is this deployment's MDM host (config mdm_host), used for
// IsOurServer; it may be empty.
func Collect(ourHost string) *shared.MDMInfo {
	return collect(ourHost)
}

// hostOf returns the lower-case host name of a URL, or "" when s isn't one.
// Only the host is ever reported: MDM URLs can carry tokens in their path or
// query.
func hostOf(s string) string {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Scheme == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// IsOurServer reports whether host (from HostOf) is this deployment's MDM
// host. ourHost may be configured as a bare host name or as a URL.
func IsOurServer(host, ourHost string) bool { return isOurServer(host, ourHost) }

func isOurServer(host, ourHost string) bool {
	ourHost = strings.TrimSpace(ourHost)
	if host == "" || ourHost == "" {
		return false
	}
	if strings.Contains(ourHost, "://") {
		ourHost = hostOf(ourHost)
	}
	return strings.EqualFold(host, strings.TrimSuffix(ourHost, "."))
}

func boolPtr(b bool) *bool { return &b }
