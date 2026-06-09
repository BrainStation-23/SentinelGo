// Package sanitize provides helpers for cleaning untrusted strings before they
// are used in sensitive sinks such as log lines.
package sanitize

import "strings"

// ForLog strips carriage-return and line-feed characters from s so that a value
// derived from configuration, system output, or remote input cannot inject
// extra lines into a log entry (log forging). Use it on any dynamic value that
// is written to a log.
func ForLog(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", ""), "\r", "")
}
