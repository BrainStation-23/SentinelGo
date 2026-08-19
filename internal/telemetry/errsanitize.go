package telemetry

import (
	"context"
	"errors"
	"io/fs"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"sentinelgo/internal/sanitize"
)

// Limits on anything derived from an error or a collector warning.
const (
	// MaxErrorLen bounds a sanitized error or warning string. Errors are for
	// triage, not forensics; the detail lives in the agent's local log.
	MaxErrorLen = 256
	// MaxWarnings caps how many warnings one CollectorResult may carry.
	MaxWarnings = 10
)

// Reason codes form the complete vocabulary that may be transmitted in a
// CollectorResult.Error. Nothing outside this list ever reaches the wire.
//
// This is the core of the design: the sanitizer CLASSIFIES an error rather than
// echoing it. Command output routinely contains hostnames, usernames, absolute
// paths, connection strings and occasionally credentials, and an error returned
// by os/exec can carry stderr verbatim. Mapping to a fixed vocabulary makes it
// impossible for that content to escape by accident.
const (
	ReasonCommandNotFound  = "command_not_found"
	ReasonPermissionDenied = "permission_denied"
	ReasonTimeout          = "timeout"
	ReasonCanceled         = "canceled"
	ReasonNotSupported     = "not_supported"
	ReasonNotFound         = "not_found"
	ReasonParseFailed      = "parse_failed"
	ReasonEmptyOutput      = "empty_output"
	ReasonWMIQueryFailed   = "wmi_query_failed"
	ReasonExitStatus       = "exit_status"
	ReasonUnexpected       = "unexpected_error"
)

// Sentinel errors collectors wrap so classification is deterministic rather
// than dependent on matching error text. Prefer these over ad-hoc errors:
//
//	return fmt.Errorf("battery: %w", telemetry.ErrNotSupported)
var (
	ErrNotSupported = errors.New("telemetry: not supported")
	ErrParseFailed  = errors.New("telemetry: parse failed")
	ErrEmptyOutput  = errors.New("telemetry: empty output")
	ErrWMIQuery     = errors.New("telemetry: wmi query failed")
)

// SanitizeError classifies err into a transmittable status and reason code.
//
// The returned string is drawn only from the Reason* vocabulary above (with an
// exit code appended for ReasonExitStatus). err.Error() is never included, so
// no command output, path, hostname or credential can leak through this path.
func SanitizeError(err error) (Status, string) {
	if err == nil {
		return StatusSuccess, ""
	}

	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return StatusTimeout, ReasonTimeout
	case errors.Is(err, context.Canceled):
		return StatusError, ReasonCanceled
	case errors.Is(err, ErrNotSupported):
		return StatusUnsupported, ReasonNotSupported
	case errors.Is(err, ErrParseFailed):
		return StatusError, ReasonParseFailed
	case errors.Is(err, ErrEmptyOutput):
		return StatusPartial, ReasonEmptyOutput
	case errors.Is(err, ErrWMIQuery):
		return StatusError, ReasonWMIQueryFailed
	case errors.Is(err, exec.ErrNotFound):
		// The tool is not installed: the data is unobtainable here, not broken.
		return StatusUnsupported, ReasonCommandNotFound
	case errors.Is(err, fs.ErrPermission):
		return StatusPermissionDenied, ReasonPermissionDenied
	case errors.Is(err, fs.ErrNotExist):
		return StatusUnsupported, ReasonNotFound
	}

	// An ExitError's Error() is "exit status N", but its Stderr field holds raw
	// command output. Take only the numeric code.
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return StatusError, ReasonExitStatus + ":" + strconv.Itoa(exitErr.ExitCode())
	}

	return StatusError, ReasonUnexpected
}

// Redaction patterns applied to agent-authored warning text. Warnings are
// written by collector authors, but they can still interpolate a path or a
// value read from the system, so they get the same treatment as any untrusted
// string before upload.
var (
	// key=value pairs whose key names a credential.
	reSecretKV = regexp.MustCompile(`(?i)\b(pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|bearer|authorization)\b\s*[:=]\s*\S+`)
	// Long unbroken hex or base64-ish runs, the usual shape of a key or hash.
	reLongToken = regexp.MustCompile(`\b[A-Za-z0-9+/_-]{32,}={0,2}\b`)
	// Windows user profile directories.
	reWinUserHome = regexp.MustCompile(`(?i)[a-z]:\\Users\\[^\\/:*?"<>|\r\n]+`)
	// Unix user home directories.
	reUnixUserHome = regexp.MustCompile(`/(?:home|Users)/[^/\s:]+`)
)

// SanitizeMessage makes an arbitrary agent-authored string safe to upload:
// credential-shaped content is redacted, user home directories are collapsed to
// a placeholder, control characters are stripped, and the result is bounded to
// MaxErrorLen on a rune boundary.
//
// It is not a substitute for SanitizeError. Never pass raw command output here
// — classify it with SanitizeError instead.
func SanitizeMessage(s string) string {
	if s == "" {
		return ""
	}

	s = sanitize.ForLog(sanitize.StripNUL(s))

	s = reSecretKV.ReplaceAllString(s, "$1=<redacted>")
	s = reWinUserHome.ReplaceAllString(s, `<userprofile>`)
	s = reUnixUserHome.ReplaceAllString(s, "<home>")
	s = reLongToken.ReplaceAllString(s, "<redacted>")

	s = strings.TrimSpace(s)
	return truncateRunes(s, MaxErrorLen)
}

// SanitizeWarnings sanitizes and caps a warning list. It returns the retained
// warnings and the number dropped, so the count can surface in telemetry health
// rather than the loss being silent.
func SanitizeWarnings(warnings []string) (kept []string, dropped int) {
	if len(warnings) == 0 {
		return nil, 0
	}

	kept = make([]string, 0, min(len(warnings), MaxWarnings))
	for _, w := range warnings {
		clean := SanitizeMessage(w)
		if clean == "" {
			continue
		}
		if len(kept) >= MaxWarnings {
			dropped++
			continue
		}
		kept = append(kept, clean)
	}
	if len(kept) == 0 {
		return nil, dropped
	}
	return kept, dropped
}

// truncateRunes shortens s to at most maxLen bytes without splitting a rune,
// appending an ellipsis marker when it cuts.
func truncateRunes(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	const marker = "..."
	limit := maxLen - len(marker)
	if limit <= 0 {
		return s[:maxLen]
	}
	// Back off to a rune boundary.
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit] + marker
}
