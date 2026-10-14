package shared

import (
	"encoding/json"
	"testing"
	"time"
)

func TestISOTime(t *testing.T) {
	loc := time.FixedZone("+06", 6*3600)
	if got := ISOTime(time.Date(2026, 10, 14, 6, 0, 0, 999, loc)); got != "2026-10-14T00:00:00Z" {
		t.Errorf("ISOTime = %q", got)
	}
}

// last_logon has three states the server tells apart: a timestamp, null
// ("never logged on") and a missing key ("unknown").
func TestLastLogonStates(t *testing.T) {
	at := time.Date(2026, 10, 13, 8, 2, 0, 0, time.UTC)
	cases := []struct {
		name string
		u    UserWithGroup
		want string
	}{
		{"logged on", UserWithGroup{Username: "a", LastLogon: LoggedOnAt(at)}, `{"username":"a","last_logon":"2026-10-13T08:02:00Z"}`},
		{"never", UserWithGroup{Username: "a", LastLogon: NeverLoggedOn()}, `{"username":"a","last_logon":null}`},
		{"unknown", UserWithGroup{Username: "a"}, `{"username":"a"}`},
	}
	for _, c := range cases {
		b, err := json.Marshal(c.u)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != c.want {
			t.Errorf("%s: got %s, want %s", c.name, b, c.want)
		}
	}
}

func TestLastLogonRoundTrip(t *testing.T) {
	in := []UserWithGroup{
		{Username: "a", LastLogon: LoggedOnAt(time.Date(2026, 10, 13, 8, 2, 0, 0, time.UTC)), IsEnabled: Bool(true)},
		{Username: "b", LastLogon: NeverLoggedOn()},
		{Username: "c"},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out []UserWithGroup
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out[0].LastLogon == nil || !out[0].LastLogon.At.Equal(in[0].LastLogon.At) || out[0].IsEnabled == nil || !*out[0].IsEnabled {
		t.Errorf("timestamp lost: %+v", out[0])
	}
	// encoding/json maps null to a nil pointer, so "never" decodes like
	// "unknown"; only the agent's encoding direction matters for the payload.
	if out[1].LastLogon != nil || out[2].LastLogon != nil {
		t.Errorf("null/missing should decode to nil: %+v %+v", out[1], out[2])
	}
	var l LastLogon
	if err := json.Unmarshal([]byte(`"not a time"`), &l); err == nil {
		t.Error("invalid timestamp should fail")
	}
}

// Compliance keys an agent can't read must be absent, never null or {}.
func TestSecurityInfoOmitsUnreadComplianceKeys(t *testing.T) {
	b, err := json.Marshal(SecurityInfo{})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"screen_lock", "password_policy", "auto_login_enabled", "guest_account_enabled",
		"remote_access", "patching", "audit_logging", "time_sync", "backup"} {
		if _, ok := m[k]; ok {
			t.Errorf("%s present in an empty SecurityInfo", k)
		}
	}

	b, _ = json.Marshal(SecurityInfo{AutoLoginEnabled: Bool(false), ScreenLock: &ScreenLockInfo{Enabled: Bool(false)}})
	_ = json.Unmarshal(b, &m)
	if m["auto_login_enabled"] != false {
		t.Errorf("a read false must be sent: %v", m["auto_login_enabled"])
	}
	if sl, _ := m["screen_lock"].(map[string]any); len(sl) != 1 || sl["enabled"] != false {
		t.Errorf("screen_lock = %v", m["screen_lock"])
	}
}
