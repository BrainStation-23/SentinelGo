package collector

// These tests exercise the pure, OS-agnostic parsing/mapping logic. They have NO
// build tag, so they run on every platform — including the Windows dev host —
// because they only test how tool output (journalctl / log show) maps to
// RawLogEntry, not any OS behavior.

import (
	"testing"
)

func TestParseJournalLine_Basic(t *testing.T) {
	line := []byte(`{"__REALTIME_TIMESTAMP":"1700000000000000","__CURSOR":"s=abc;i=1",` +
		`"MESSAGE":"hello world","PRIORITY":"3","SYSLOG_IDENTIFIER":"sshd","_PID":"123"}`)

	entry, cursor, ok := parseJournalLine(line)
	if !ok {
		t.Fatal("expected ok=true for valid journal line")
	}
	if entry.Source != "journal" {
		t.Errorf("Source = %q, want journal", entry.Source)
	}
	if entry.RawMessage != "hello world" {
		t.Errorf("RawMessage = %q, want %q", entry.RawMessage, "hello world")
	}
	if entry.Severity != "3" {
		t.Errorf("Severity = %q, want 3", entry.Severity)
	}
	if cursor != "s=abc;i=1" {
		t.Errorf("cursor = %q, want s=abc;i=1", cursor)
	}
	if entry.Metadata["identifier"] != "sshd" {
		t.Errorf("Metadata[identifier] = %q, want sshd", entry.Metadata["identifier"])
	}
	if entry.Metadata["_pid"] != "123" {
		t.Errorf("Metadata[_pid] = %q, want 123", entry.Metadata["_pid"])
	}
	if entry.Timestamp.Unix() != 1700000000 {
		t.Errorf("Timestamp.Unix() = %d, want 1700000000", entry.Timestamp.Unix())
	}
}

func TestParseJournalLine_MessageAsByteArray(t *testing.T) {
	// journalctl encodes non-UTF8 MESSAGE values as an array of byte values.
	line := []byte(`{"MESSAGE":[104,105],"PRIORITY":"6"}`)
	entry, _, ok := parseJournalLine(line)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if entry.RawMessage != "hi" {
		t.Errorf("RawMessage = %q, want %q", entry.RawMessage, "hi")
	}
}

func TestParseJournalLine_Invalid(t *testing.T) {
	if _, _, ok := parseJournalLine([]byte(`not json`)); ok {
		t.Error("expected ok=false for invalid JSON")
	}
}

func TestParseJournalTimestamp(t *testing.T) {
	got := parseJournalTimestamp("1700000000000000")
	if got.Unix() != 1700000000 {
		t.Errorf("Unix() = %d, want 1700000000", got.Unix())
	}
	// Invalid values fall back to "now" (just assert it doesn't return zero time).
	if parseJournalTimestamp("garbage").IsZero() {
		t.Error("expected non-zero fallback time")
	}
}

func TestInferSyslogSeverity(t *testing.T) {
	cases := map[string]string{
		"connection error occurred": "3",
		"login failed for user":     "3",
		"low disk warning":          "4",
		"kernel panic":              "2",
		"system emergency halt":     "0",
		"routine status update":     "6",
	}
	for line, want := range cases {
		if got := inferSyslogSeverity(line); got != want {
			t.Errorf("inferSyslogSeverity(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestParseSyslogTimestamp(t *testing.T) {
	got := parseSyslogTimestamp("Jan  2 15:04:05 host sshd[1]: hello")
	if got.Month() != 1 || got.Day() != 2 {
		t.Errorf("got %v, want Jan 2", got)
	}
	// A too-short / unparseable line falls back to a non-zero time.
	if parseSyslogTimestamp("short").IsZero() {
		t.Error("expected non-zero fallback time")
	}
}

func TestParseMacFileTimestamp(t *testing.T) {
	got := parseMacFileTimestamp("Apr 19 14:30:00 host kernel: hi")
	if got.Month() != 4 || got.Day() != 19 {
		t.Errorf("got %v, want Apr 19", got)
	}
	if parseMacFileTimestamp("x").IsZero() {
		t.Error("expected non-zero fallback time")
	}
}

func TestParseMacLogShowLine(t *testing.T) {
	line := []byte(`{"timestamp":"2024-04-19 14:30:00.123456-0700","messageType":"Error",` +
		`"eventMessage":"disk failure","category":"kernel","subsystem":"com.apple.kernel","process":"kernel"}`)

	entry, ok := parseMacLogShowLine(line)
	if !ok {
		t.Fatal("expected ok=true for valid log show line")
	}
	if entry.Source != "oslog" {
		t.Errorf("Source = %q, want oslog", entry.Source)
	}
	if entry.RawMessage != "disk failure" {
		t.Errorf("RawMessage = %q, want %q", entry.RawMessage, "disk failure")
	}
	if entry.Severity != "3" {
		t.Errorf("Severity = %q, want 3 (Error)", entry.Severity)
	}
	if entry.Metadata["category"] != "kernel" {
		t.Errorf("Metadata[category] = %q, want kernel", entry.Metadata["category"])
	}
	if entry.Metadata["subsystem"] != "com.apple.kernel" {
		t.Errorf("Metadata[subsystem] = %q, want com.apple.kernel", entry.Metadata["subsystem"])
	}
	if entry.Timestamp.Year() != 2024 {
		t.Errorf("Timestamp.Year() = %d, want 2024", entry.Timestamp.Year())
	}
}

func TestParseMacLogShowLine_SkipsNonEntry(t *testing.T) {
	// `log show` ndjson can contain metadata lines with no message/timestamp.
	if _, ok := parseMacLogShowLine([]byte(`{"foo":"bar"}`)); ok {
		t.Error("expected ok=false for non-entry line")
	}
	if _, ok := parseMacLogShowLine([]byte(`not json`)); ok {
		t.Error("expected ok=false for invalid JSON")
	}
}

func TestMacMessageTypeToSeverity(t *testing.T) {
	cases := map[string]string{
		"Debug":   "7",
		"Info":    "6",
		"Default": "5",
		"Notice":  "5",
		"Error":   "3",
		"Fault":   "2",
		"":        "6",
		"weird":   "6",
	}
	for in, want := range cases {
		if got := macMessageTypeToSeverity(in); got != want {
			t.Errorf("macMessageTypeToSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseMacShowTimestamp(t *testing.T) {
	got := parseMacShowTimestamp("2024-04-19 14:30:00.123456-0700")
	if got.Year() != 2024 || got.Month() != 4 || got.Day() != 19 {
		t.Errorf("got %v, want 2024-04-19", got)
	}
	if parseMacShowTimestamp("garbage").IsZero() {
		t.Error("expected non-zero fallback time")
	}
}

func TestInferMacSeverity(t *testing.T) {
	cases := map[string]string{
		"app error":        "3",
		"mount failed":     "3",
		"thermal warning":  "4",
		"kernel panic now": "2",
		"normal message":   "6",
	}
	for line, want := range cases {
		if got := inferMacSeverity(line); got != want {
			t.Errorf("inferMacSeverity(%q) = %q, want %q", line, got, want)
		}
	}
}
