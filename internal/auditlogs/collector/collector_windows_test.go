//go:build windows

package collector

// Pure-logic tests for the Windows collector. They run on the Windows host. The
// event-reading path (EvtQuery/EvtRender) needs real OS handles and is covered
// by integration runs, not here.

import (
	"strings"
	"testing"
	"time"
)

func TestGenerateSource(t *testing.T) {
	cases := map[string]string{
		"Security": "windows_security",
		"Microsoft-Windows-PowerShell/Operational": "windows_microsoft_windows_powershell_operational",
		"Windows Defender/Operational":             "windows_windows_defender_operational",
	}
	for in, want := range cases {
		if got := generateSource(in); got != want {
			t.Errorf("generateSource(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWindowsLevelToSeverity(t *testing.T) {
	cases := map[int]string{
		1: "2", // Critical
		2: "3", // Error
		3: "4", // Warning
		4: "6", // Information
		5: "7", // Verbose
		9: "6", // unknown -> info
	}
	for level, want := range cases {
		if got := windowsLevelToSeverity(level); got != want {
			t.Errorf("windowsLevelToSeverity(%d) = %q, want %q", level, got, want)
		}
	}
}

func TestBuildFirstRunQuery(t *testing.T) {
	const day = 24 * time.Hour
	cases := []struct {
		base     string
		lookback time.Duration
		want     string
	}{
		{"*", 3 * day, "*[System[TimeCreated[timediff(@SystemTime) <= 259200000]]]"},
		{"*[System[(EventID=4624 or EventID=4625)]]", day,
			"*[System[((EventID=4624 or EventID=4625)) and TimeCreated[timediff(@SystemTime) <= 86400000]]]"},
		{"*[System[(EventID=4624)]]", 0, "*[System[(EventID=4624)]]"},
	}
	for _, c := range cases {
		if got := buildFirstRunQuery(c.base, c.lookback); got != c.want {
			t.Errorf("buildFirstRunQuery(%q, %s) = %q, want %q", c.base, c.lookback, got, c.want)
		}
	}
}

// Every channel's first-run query carries the time bound (#437).
func TestChannels_FirstRunQueriesAreBounded(t *testing.T) {
	for _, ch := range channels {
		q := buildFirstRunQuery(ch.query, 3*24*time.Hour)
		if !strings.Contains(q, "timediff(@SystemTime) <= 259200000") {
			t.Errorf("%s (%s): first-run query %q has no time bound", ch.name, ch.checkpointKey(), q)
		}
	}
}

// System events 35 and 24 match exactly one System query (#436): the Level 1-4
// query excludes them and the time-service query collects them.
func TestChannels_TimeServiceEventsCollectedOnce(t *testing.T) {
	var matches int
	for _, ch := range channels {
		if ch.name != "System" {
			continue
		}
		for _, id := range []string{"35", "24"} {
			included := strings.Contains(ch.query, "EventID="+id+")") || strings.Contains(ch.query, "EventID="+id+" ")
			excluded := strings.Contains(ch.query, "EventID!="+id)
			levelQuery := strings.Contains(ch.query, "Level=4")
			if (included || levelQuery) && !excluded {
				matches++
			}
		}
	}
	if matches != 2 {
		t.Errorf("events 35 and 24 match %d System queries in total, want 2 (one each)", matches)
	}
}

func TestApplyEventData(t *testing.T) {
	md := map[string]string{}
	msg := applyEventData(md, []eventDataField{
		{Name: "TargetUserName", Value: "alice"},
		{Name: "LogonType", Value: "2"},
		{Name: "", Value: "unnamed value"},
		{Name: "Empty", Value: ""},
	})
	if msg != "unnamed value" {
		t.Errorf("message = %q, want only the unnamed value", msg)
	}
	if md["TargetUserName"] != "alice" || md["LogonType"] != "2" {
		t.Errorf("named fields not kept as keys: %v", md)
	}
	if v, ok := md["Empty"]; !ok || v != "" {
		t.Errorf("empty named field should still be a key; got %v", md)
	}
}
