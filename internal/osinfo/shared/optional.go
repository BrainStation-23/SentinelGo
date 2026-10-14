package shared

import (
	"encoding/json"
	"time"
)

// The compliance telemetry fields (#172) are optional: a nil pointer leaves
// the key out of the payload, which the server reads as "unknown". These
// helpers build the pointers.

// Bool returns a pointer to b.
func Bool(b bool) *bool { return &b }

// Int returns a pointer to n.
func Int(n int) *int { return &n }

// Int64 returns a pointer to n.
func Int64(n int64) *int64 { return &n }

// ISOTime formats t as ISO 8601 UTC with second precision, the timestamp
// format the inventory contract uses (e.g. "2026-10-09T02:14:00Z").
func ISOTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// LastLogon is a local account's most recent logon. The contract gives
// last_logon three states: a timestamp, null for "never logged on", and a
// missing key for "unknown". A nil *LastLogon covers the last (omitempty);
// a LastLogon with a zero At marshals as null.
type LastLogon struct {
	At time.Time
}

// NeverLoggedOn is the LastLogon of an account that has never logged on.
func NeverLoggedOn() *LastLogon { return &LastLogon{} }

// LoggedOnAt is the LastLogon of an account that last logged on at t.
func LoggedOnAt(t time.Time) *LastLogon { return &LastLogon{At: t} }

// MarshalJSON encodes the logon time as ISO 8601 UTC, or null for never.
func (l LastLogon) MarshalJSON() ([]byte, error) {
	if l.At.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(ISOTime(l.At))
}

// UnmarshalJSON accepts what MarshalJSON writes. encoding/json handles a
// JSON null itself by leaving the *LastLogon nil, so only strings reach here.
func (l *LastLogon) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		l.At = time.Time{}
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return err
	}
	l.At = t
	return nil
}
