//go:build windows

package collector

// Tests for the Windows collector. They run on the Windows host. Reading and
// rendering events is covered by integration runs; the queries are checked
// against the real EvtQuery (TestChannels_QueriesAreValid).

import (
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
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
// TestSourceConstants keeps the exported source names (used by the parser to
// grade events, #484) in step with the channel names they come from.
func TestSourceConstants(t *testing.T) {
	for channel, want := range map[string]string{
		"Security": SourceWindowsSecurity,
		"System":   SourceWindowsSystem,
		"Microsoft-Windows-Windows Defender/Operational":                         SourceWindowsDefender,
		"Microsoft-Windows-PowerShell/Operational":                               SourceWindowsPowerShell,
		"Microsoft-Windows-TaskScheduler/Operational":                            SourceWindowsTaskScheduler,
		"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall":     SourceWindowsFirewall,
		"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational": SourceWindowsRemoteDesktop,
	} {
		if got := generateSource(channel); got != want {
			t.Errorf("generateSource(%q) = %q, constant is %q", channel, got, want)
		}
	}
	sources := map[string]bool{}
	for _, ch := range channels {
		sources[ch.source] = true
	}
	for _, s := range []string{SourceWindowsSecurity, SourceWindowsSystem, SourceWindowsDefender,
		SourceWindowsPowerShell, SourceWindowsTaskScheduler, SourceWindowsFirewall, SourceWindowsRemoteDesktop} {
		if !sources[s] {
			t.Errorf("no channel has source %q", s)
		}
	}
}

// TestChannels_QueriesAreValid runs every channel's query, as-is, after a
// checkpoint and bounded for a first run, plus the real-time query, through
// the real EvtQuery (#484). A channel the host lacks, or the Security log
// without elevation, is skipped; an invalid XPath fails.
func TestChannels_QueriesAreValid(t *testing.T) {
	const (
		errAccessDenied    = windows.Errno(5)
		errInvalidQuery    = windows.Errno(15001)
		errChannelNotFound = windows.Errno(15007)
	)
	type q struct{ channel, query string }
	var qs []q
	for _, ch := range channels {
		qs = append(qs,
			q{ch.name, ch.query},
			q{ch.name, buildXPathQuery(ch.query, 12345)},
			q{ch.name, buildFirstRunQuery(ch.query, 72*time.Hour)})
	}
	qs = append(qs, q{"Security", securityRealTimeQuery})
	for _, c := range qs {
		path, _ := windows.UTF16PtrFromString(c.channel)
		query, _ := windows.UTF16PtrFromString(c.query)
		h, _, err := procEvtQuery.Call(0, uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(query)),
			EvtQueryChannelPath|EvtQueryForwardDirection)
		if h != 0 {
			_, _, _ = procEvtClose.Call(h)
			continue
		}
		switch err {
		case errAccessDenied, errChannelNotFound:
			t.Logf("skipped %s: %v", c.channel, err)
		case errInvalidQuery:
			t.Errorf("invalid query on %s: %s", c.channel, c.query)
		default:
			t.Errorf("EvtQuery on %s (%s): %v", c.channel, c.query, err)
		}
	}
}

// TestChannels_SystemQueryKeepsGradedEvents: the System query asks for errors
// and the two events the parser grades up (#484).
func TestChannels_SystemQueryKeepsGradedEvents(t *testing.T) {
	for _, ch := range channels {
		if ch.source != SourceWindowsSystem {
			continue
		}
		for _, want := range []string{"Level=1", "Level=2", "EventID=104", "EventID=7045"} {
			if !strings.Contains(ch.query, want) {
				t.Errorf("System query %q lacks %s", ch.query, want)
			}
		}
		return
	}
	t.Fatal("no System channel")
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
