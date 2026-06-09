package collector

// This file holds the pure, OS-agnostic parsing and mapping logic shared by the
// platform collectors. It has NO build tag on purpose: the logic is about the
// *output format* of tools like `journalctl` and `log show`, not about the host
// OS, so it can be unit-tested on any platform (including the Windows dev host).
// The OS-specific files (collector_linux.go, collector_darwin.go) supply the
// actual data; these functions turn bytes into RawLogEntry values.

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"time"
)

// macLogTimestampLayout is the timestamp format emitted by `log show`.
const macLogTimestampLayout = "2006-01-02 15:04:05.999999-0700"

// journalMetaFields are the systemd journal fields surfaced as metadata.
// MESSAGE and PRIORITY are handled specially; SYSLOG_IDENTIFIER maps to
// "identifier"; the rest become lower-cased metadata keys.
var journalMetaFields = []string{
	"SYSLOG_IDENTIFIER",
	"_SYSTEMD_UNIT",
	"_PID",
	"_UID",
	"_HOSTNAME",
	"_TRANSPORT",
	"_COMM",
	"_EXE",
}

// parseJournalLine converts a single `journalctl -o json` line into a RawLogEntry
// and the entry's opaque cursor. Returns ok=false for lines that cannot be decoded.
func parseJournalLine(line []byte) (entry RawLogEntry, cursor string, ok bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(line, &fields); err != nil {
		return RawLogEntry{}, "", false
	}

	entry = RawLogEntry{
		Source:     "journal",
		Timestamp:  parseJournalTimestamp(journalString(fields, "__REALTIME_TIMESTAMP")),
		RawMessage: journalString(fields, "MESSAGE"),
		Severity:   journalString(fields, "PRIORITY"),
		Metadata:   make(map[string]string),
	}

	if id := journalString(fields, "SYSLOG_IDENTIFIER"); id != "" {
		entry.Metadata["identifier"] = id
	}
	for _, f := range journalMetaFields {
		if f == "SYSLOG_IDENTIFIER" {
			continue
		}
		if val := journalString(fields, f); val != "" {
			entry.Metadata[strings.ToLower(f)] = val
		}
	}

	return entry, journalString(fields, "__CURSOR"), true
}

// journalString extracts a journal field as a string. journalctl encodes most
// fields as JSON strings, but binary/non-UTF8 values are encoded as an array of
// byte values — this handles both.
func journalString(fields map[string]json.RawMessage, key string) string {
	raw, ok := fields[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var bytesArr []int
	if err := json.Unmarshal(raw, &bytesArr); err == nil {
		b := make([]byte, len(bytesArr))
		for i, v := range bytesArr {
			if v < 0 || v > math.MaxUint8 {
				return ""
			}
			b[i] = byte(v)
		}
		return string(b)
	}
	return ""
}

// parseJournalTimestamp converts a __REALTIME_TIMESTAMP (microseconds since the
// Unix epoch, as a string) into a time.Time, falling back to now on error.
func parseJournalTimestamp(s string) time.Time {
	if s == "" {
		return time.Now()
	}
	usec, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Now()
	}
	return time.UnixMicro(usec)
}

// parseSyslogTimestamp attempts to extract a timestamp from a syslog-format line.
// Falls back to current time if parsing fails.
func parseSyslogTimestamp(line string) time.Time {
	// Standard syslog format: "Mon Jan  2 15:04:05"
	if len(line) >= 15 {
		layouts := []string{
			"Jan  2 15:04:05",
			"Jan 2 15:04:05",
			"2006-01-02T15:04:05",
			time.RFC3339,
		}
		for _, layout := range layouts {
			end := len(layout)
			if end > len(line) {
				end = len(line)
			}
			if t, err := time.Parse(layout, line[:end]); err == nil {
				// Syslog doesn't include year -- use current year
				if t.Year() == 0 {
					t = t.AddDate(time.Now().Year(), 0, 0)
					if t.After(time.Now()) {
						t = t.AddDate(-1, 0, 0)
					}
				}
				return t
			}
		}
	}
	return time.Now()
}

// inferSyslogSeverity guesses severity from keywords in a syslog/file log line.
func inferSyslogSeverity(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "error") || strings.Contains(lower, "fail"):
		return "3" // error
	case strings.Contains(lower, "warn"):
		return "4" // warning
	case strings.Contains(lower, "crit") || strings.Contains(lower, "panic"):
		return "2" // critical
	case strings.Contains(lower, "emerg"):
		return "0" // emergency
	default:
		return "6" // info
	}
}

// macLogShowEntry is the subset of `log show --style ndjson` fields we consume.
type macLogShowEntry struct {
	Timestamp    string `json:"timestamp"`
	MessageType  string `json:"messageType"`
	EventMessage string `json:"eventMessage"`
	Category     string `json:"category"`
	Subsystem    string `json:"subsystem"`
	Process      string `json:"process"`
}

// parseMacLogShowLine converts a single `log show --style ndjson` line into a
// RawLogEntry. Returns ok=false for metadata/non-entry lines.
func parseMacLogShowLine(line []byte) (RawLogEntry, bool) {
	var raw macLogShowEntry
	if err := json.Unmarshal(line, &raw); err != nil {
		return RawLogEntry{}, false
	}
	if raw.EventMessage == "" && raw.Timestamp == "" {
		return RawLogEntry{}, false
	}

	entry := RawLogEntry{
		Timestamp:  parseMacShowTimestamp(raw.Timestamp),
		Source:     "oslog",
		RawMessage: raw.EventMessage,
		Severity:   macMessageTypeToSeverity(raw.MessageType),
		Metadata:   make(map[string]string),
	}
	if raw.Category != "" {
		entry.Metadata["category"] = raw.Category
	}
	if raw.Subsystem != "" {
		entry.Metadata["subsystem"] = raw.Subsystem
	}
	if raw.Process != "" {
		entry.Metadata["process"] = raw.Process
	}
	return entry, true
}

// parseMacShowTimestamp parses the timestamp emitted by `log show`.
func parseMacShowTimestamp(s string) time.Time {
	if s == "" {
		return time.Now()
	}
	if t, err := time.Parse(macLogTimestampLayout, s); err == nil {
		return t
	}
	return time.Now()
}

// macMessageTypeToSeverity maps a `log show` messageType to a syslog-style severity string.
func macMessageTypeToSeverity(messageType string) string {
	switch strings.ToLower(messageType) {
	case "debug":
		return "7"
	case "info":
		return "6"
	case "default", "notice":
		return "5"
	case "error":
		return "3"
	case "fault":
		return "2"
	default:
		return "6"
	}
}

// parseMacFileTimestamp parses timestamps from macOS system.log format.
func parseMacFileTimestamp(line string) time.Time {
	// macOS system.log format: "Apr 19 14:30:00"
	layouts := []string{
		"Jan  2 15:04:05",
		"Jan 2 15:04:05",
		time.RFC3339,
	}

	for _, layout := range layouts {
		end := len(layout)
		if end > len(line) {
			continue
		}
		if t, err := time.Parse(layout, line[:end]); err == nil {
			if t.Year() == 0 {
				t = t.AddDate(time.Now().Year(), 0, 0)
				if t.After(time.Now()) {
					t = t.AddDate(-1, 0, 0)
				}
			}
			return t
		}
	}
	return time.Now()
}

// inferMacSeverity guesses severity from keywords in a macOS log line.
func inferMacSeverity(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "error") || strings.Contains(lower, "fail"):
		return "3"
	case strings.Contains(lower, "warn"):
		return "4"
	case strings.Contains(lower, "crit") || strings.Contains(lower, "panic"):
		return "2"
	default:
		return "6"
	}
}
