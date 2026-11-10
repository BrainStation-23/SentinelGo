package parser

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"sentinelgo/internal/auditlogs/collector"
)

func decodeEventData(t *testing.T, b json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("event_data is not a JSON object: %v (%s)", err, b)
	}
	return m
}

// A Windows event with 40 KB of EventData is trimmed to the target and keeps
// the fields that identify it (#438).
func TestParse_CapsLargeWindowsEvent(t *testing.T) {
	md := map[string]string{
		"provider":      "Microsoft-Windows-PowerShell",
		"channel":       "Microsoft-Windows-PowerShell/Operational",
		"computer":      "WS-01",
		"record_id":     "123456",
		"ScriptBlock":   strings.Repeat("Get-Process; ", 2500), // ~32 KB
		"Path":          strings.Repeat("C:\\Temp\\é\\", 700),  // ~7 KB, multi-byte
		"MessageNumber": "1",
	}
	raw := collector.RawLogEntry{Timestamp: time.Now(), Source: "windows_x", EventID: "4104", Metadata: md}

	logs := NewParser().Parse([]collector.RawLogEntry{raw}, ParserConfig{})
	ed := logs[0].EventData
	if len(ed) > 9500 {
		t.Fatalf("event_data is %d bytes, want <= 9500", len(ed))
	}
	m := decodeEventData(t, ed)
	if m["truncated"] != true {
		t.Errorf("truncated = %v, want true", m["truncated"])
	}
	if ob, _ := m["original_bytes"].(float64); ob < 39000 {
		t.Errorf("original_bytes = %v, want the untrimmed size (~40 KB)", m["original_bytes"])
	}
	for k, want := range map[string]string{"event_id": "4104", "provider": md["provider"], "record_id": "123456", "channel": md["channel"], "MessageNumber": "1"} {
		if m[k] != want {
			t.Errorf("%s = %v, want %q", k, m[k], want)
		}
	}
	for k, v := range m {
		if s, ok := v.(string); ok && !utf8.ValidString(s) {
			t.Errorf("%s was cut inside a UTF-8 sequence", k)
		}
	}
}

// A typical 4624 logon event has no joined-message duplicate and keeps its
// named fields unchanged (#438).
func TestParse_WindowsLogonHasNoDuplicateMessage(t *testing.T) {
	md := map[string]string{
		"provider": "Microsoft-Windows-Security-Auditing", "channel": "Security", "record_id": "42",
		"TargetUserName": "alice", "TargetDomainName": "CORP", "LogonType": "2", "IpAddress": "10.0.0.5",
	}
	// The Windows collector leaves RawMessage empty when every Data field is named.
	raw := collector.RawLogEntry{Timestamp: time.Now(), Source: "windows_security", EventID: "4624", Metadata: md}
	m := decodeEventData(t, NewParser().Parse([]collector.RawLogEntry{raw}, ParserConfig{})[0].EventData)
	if _, ok := m["message"]; ok {
		t.Errorf("message = %v, want none", m["message"])
	}
	if _, ok := m["truncated"]; ok {
		t.Error("a small event must not be marked truncated")
	}
	for k, v := range md {
		if m[k] != v {
			t.Errorf("%s = %v, want %q", k, m[k], v)
		}
	}
}

// The server's limit from the enqueue response replaces the default.
func TestParse_UsesServerLimit(t *testing.T) {
	raw := collector.RawLogEntry{Timestamp: time.Now(), Source: "s", RawMessage: strings.Repeat("a", 5000)}
	ed := NewParser().Parse([]collector.RawLogEntry{raw}, ParserConfig{MaxEventDataBytes: 2000})[0].EventData
	if len(ed) > EventDataTarget(2000) {
		t.Errorf("event_data is %d bytes, want <= %d", len(ed), EventDataTarget(2000))
	}
}

// An unparseable timestamp (zero time) becomes the collection time and the
// row says so (#437).
func TestParse_MarksCollectedTimestamp(t *testing.T) {
	before := time.Now().Add(-time.Second)
	raw := collector.RawLogEntry{Source: "syslog", RawMessage: "no timestamp here"}
	l := NewParser().Parse([]collector.RawLogEntry{raw}, ParserConfig{})[0]
	ts, err := time.Parse(time.RFC3339, l.Timestamp)
	if err != nil || ts.Before(before.Truncate(time.Second)) {
		t.Errorf("created_at = %q, want about now", l.Timestamp)
	}
	if m := decodeEventData(t, l.EventData); m["timestamp_source"] != "collected" {
		t.Errorf("timestamp_source = %v, want collected", m["timestamp_source"])
	}

	raw.Timestamp = time.Now()
	if m := decodeEventData(t, NewParser().Parse([]collector.RawLogEntry{raw}, ParserConfig{})[0].EventData); m["timestamp_source"] != nil {
		t.Errorf("a parsed timestamp must not be marked; got %v", m["timestamp_source"])
	}
}

func TestCapEventData(t *testing.T) {
	small := json.RawMessage(`{"a":"b"}`)
	if got := CapEventData(small, 100); string(got) != string(small) {
		t.Errorf("small data changed: %s", got)
	}
	if m := decodeEventData(t, CapEventData(json.RawMessage(`[`+strings.Repeat(`1,`, 100)+`1]`), 50)); m["truncated"] != true {
		t.Errorf("non-object data: got %v", m)
	}
	// Escaped characters take more bytes than their length; still fits.
	big, _ := json.Marshal(map[string]string{"x": strings.Repeat("<\"\n", 2000)})
	if got := CapEventData(big, 500); len(got) > 500 {
		t.Errorf("escaped data: %d bytes, want <= 500", len(got))
	}
}
