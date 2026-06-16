// Package sanitize provides helpers for cleaning untrusted strings before they
// are used in sensitive sinks such as log lines or database payloads.
package sanitize

import (
	"bytes"
	"strings"
)

// jsonNULEscape is how encoding/json renders a NUL byte (U+0000) inside a string:
// the six-byte ASCII sequence backslash-u-zero-zero-zero-zero.
var jsonNULEscape = []byte("\\u0000")

// ForLog strips carriage-return and line-feed characters from s so that a value
// derived from configuration, system output, or remote input cannot inject
// extra lines into a log entry (log forging). Use it on any dynamic value that
// is written to a log.
func ForLog(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", ""), "\r", "")
}

// StripNUL removes NUL (U+0000) bytes from s. Postgres rejects NUL in text/jsonb
// columns, so any value derived from OS command output, file contents, or binary
// log fields must have NULs removed before it reaches the backend.
func StripNUL(s string) string {
	if !strings.ContainsRune(s, 0) {
		return s
	}
	return strings.ReplaceAll(s, "\x00", "")
}

// StripJSONNUL removes NUL characters from already-marshaled JSON so the payload
// is accepted by Postgres text/jsonb columns, which reject U+0000. encoding/json
// renders a real NUL byte as the six-byte escape backslash-u-zero-zero-zero-zero.
// StripJSONNUL removes only escapes the encoder produced for a real NUL byte
// (one preceded by an even number of backslashes), leaving any literal text that
// merely looks like that escape (which the encoder writes with a doubled leading
// backslash) intact — so the result is always still valid JSON.
func StripJSONNUL(b []byte) []byte {
	if !bytes.Contains(b, jsonNULEscape) {
		return b
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); {
		if b[i] != '\\' {
			out = append(out, b[i])
			i++
			continue
		}
		// Consume the full run of consecutive backslashes.
		j := i
		for j < len(b) && b[j] == '\\' {
			j++
		}
		runLen := j - i
		// An odd run means the final backslash escapes the following character; if
		// that is "u0000" it is an encoded NUL, so emit runLen-1 backslashes and drop
		// the escape. An even run is literal backslashes, so it is left untouched.
		if runLen%2 == 1 && bytes.HasPrefix(b[j:], []byte("u0000")) {
			for k := 0; k < runLen-1; k++ {
				out = append(out, '\\')
			}
			i = j + len("u0000")
			continue
		}
		for k := 0; k < runLen; k++ {
			out = append(out, '\\')
		}
		i = j
	}
	return out
}
