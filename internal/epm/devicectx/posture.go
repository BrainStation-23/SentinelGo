package devicectx

import (
	"strings"

	"sentinelgo/internal/osinfo/security"
	"sentinelgo/internal/osinfo/system"
)

// postureResult is what collectPostureReal produces for provider.go's
// collectPosture to fold into the shared snapshot. err set means the whole
// cycle failed (see postureCollectorFn's caller); the zero value of every
// other field is never observed by a caller in that case.
type postureResult struct {
	diskEncryption  string
	secureBoot      string
	firewallState   string
	antivirusHealth string
	compliance      string
	tpmStatus       string
	osVersion       string
	err             error
}

// collectPostureReal wraps osinfo/security.Collect, translating its
// Capitalized human-facing enums ("Enabled", "Partially Encrypted", …) into
// the lowercase vocabulary ContextSnapshot's fields document and
// matchers_context.go's posturalValue depends on (the literal string
// "unknown" is what makes a value Unknown — an un-normalized "Unknown" would
// silently be treated as a matchable literal instead).
//
// security.Collect() never returns an error — probe failures are swallowed
// internally and reported as zero/"Unknown" fields, per its own doc comment
// — so this always returns a nil error. The error return exists so the
// postureCollectorFn seam can be replaced with a fake that DOES fail, for
// collectPosture's error-handling path in provider.go.
func collectPostureReal() postureResult {
	info := security.Collect()
	return postureResult{
		diskEncryption:  normalizeDiskEncryption(info.DeviceEncryption.EncryptionStatus),
		secureBoot:      normalizeEnabledVocab(info.HardwareSecurity.SecureBootStatus),
		firewallState:   normalizeFirewallState(info.FirewallSecurity.FirewallState),
		antivirusHealth: normalizeAntivirusHealth(info.PostureSummary.AntivirusHealth),
		compliance:      strings.ToLower(strings.TrimSpace(info.PostureSummary.OverallScore)),
		tpmStatus:       normalizeEnabledVocab(info.HardwareSecurity.TPMStatus),
		osVersion:       system.GetOSInformation().OSVersion,
	}
}

func normalizeDiskEncryption(v string) string {
	switch strings.TrimSpace(v) {
	case "Encrypted":
		return "encrypted"
	case "Unencrypted":
		return "unencrypted"
	case "Partially Encrypted":
		return "partial"
	default:
		return "unknown"
	}
}

func normalizeFirewallState(v string) string {
	switch strings.TrimSpace(v) {
	case "Enabled":
		return "enabled"
	case "Disabled":
		return "disabled"
	case "Partially Enabled":
		return "partial"
	default:
		return "unknown"
	}
}

func normalizeAntivirusHealth(v string) string {
	switch strings.TrimSpace(v) {
	case "Healthy":
		return "healthy"
	case "Unhealthy":
		return "unhealthy"
	case "None":
		return "none"
	default:
		return "unknown"
	}
}

// normalizeEnabledVocab handles the common "Enabled"/"Disabled"/"Unsupported"
// tri-plus-unknown vocabulary shared by SecureBootStatus and TPMStatus.
func normalizeEnabledVocab(v string) string {
	switch strings.TrimSpace(v) {
	case "Enabled":
		return "enabled"
	case "Disabled":
		return "disabled"
	case "Unsupported":
		return "unsupported"
	default:
		return "unknown"
	}
}
