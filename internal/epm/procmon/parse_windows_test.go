//go:build windows

package procmon

import (
	"testing"

	"sentinelgo/internal/epm"
)

const sample4688XML = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>
    <EventID>4688</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <TimeCreated SystemTime="2026-07-29T10:15:30.1234567Z"/>
    <EventRecordID>123456</EventRecordID>
    <Channel>Security</Channel>
    <Computer>DESKTOP-ABC123</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-1111111111-2222222222-3333333333-1001</Data>
    <Data Name="SubjectUserName">alice</Data>
    <Data Name="SubjectDomainName">CORP</Data>
    <Data Name="SubjectLogonId">0x3e7</Data>
    <Data Name="NewProcessId">0x1a2c</Data>
    <Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
    <Data Name="TokenElevationType">%%1937</Data>
    <Data Name="ProcessId">0x1000</Data>
    <Data Name="CommandLine">cmd.exe /c dir</Data>
    <Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
  </EventData>
</Event>`

const sample4689XML = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>
    <EventID>4689</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2026-07-29T10:16:00.0000000Z"/>
    <EventRecordID>123457</EventRecordID>
    <Channel>Security</Channel>
    <Computer>DESKTOP-ABC123</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-1111111111-2222222222-3333333333-1001</Data>
    <Data Name="SubjectUserName">alice</Data>
    <Data Name="SubjectDomainName">CORP</Data>
    <Data Name="SubjectLogonId">0x3e7</Data>
    <Data Name="Status">0x0</Data>
    <Data Name="ProcessId">0x1a2c</Data>
    <Data Name="ProcessName">C:\Windows\System32\cmd.exe</Data>
    <Data Name="ExitStatus">0x0</Data>
  </EventData>
</Event>`

func TestParseWindowsProcessEventXML_4688(t *testing.T) {
	ev, ok := parseWindowsProcessEventXML(sample4688XML)
	if !ok {
		t.Fatal("parseWindowsProcessEventXML returned ok=false")
	}
	if ev.Kind != EventStart {
		t.Errorf("Kind = %v, want EventStart", ev.Kind)
	}
	if ev.PID != 0x1a2c {
		t.Errorf("PID = %#x, want 0x1a2c", ev.PID)
	}
	if ev.ParentPID != 0x1000 {
		t.Errorf("ParentPID = %#x, want 0x1000", ev.ParentPID)
	}
	if ev.ImagePath != `C:\Windows\System32\cmd.exe` {
		t.Errorf("ImagePath = %q", ev.ImagePath)
	}
	if ev.CommandLine != "cmd.exe /c dir" {
		t.Errorf("CommandLine = %q", ev.CommandLine)
	}
	if ev.UserID != "S-1-5-21-1111111111-2222222222-3333333333-1001" {
		t.Errorf("UserID = %q", ev.UserID)
	}
	if ev.Elevated != epm.TriTrue {
		t.Errorf("Elevated = %v, want TriTrue (TokenElevationType=%%%%1937)", ev.Elevated)
	}
	if ev.Source != "etw4688" {
		t.Errorf("Source = %q, want etw4688", ev.Source)
	}
	want := HavePID | HaveParentPID | HaveImagePath | HaveCommandLine | HaveUserID | HaveElevated
	if ev.Have != want {
		t.Errorf("Have = %b, want %b", ev.Have, want)
	}
	if ev.ObservedAt.Year() != 2026 {
		t.Errorf("ObservedAt = %v, want parsed from TimeCreated", ev.ObservedAt)
	}
}

func TestParseWindowsProcessEventXML_4689(t *testing.T) {
	ev, ok := parseWindowsProcessEventXML(sample4689XML)
	if !ok {
		t.Fatal("parseWindowsProcessEventXML returned ok=false")
	}
	if ev.Kind != EventExit {
		t.Errorf("Kind = %v, want EventExit", ev.Kind)
	}
	if ev.PID != 0x1a2c {
		t.Errorf("PID = %#x, want 0x1a2c", ev.PID)
	}
	if ev.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", ev.ExitCode)
	}
	if !ev.Have.Has(HaveExitCode) {
		t.Errorf("Have missing HaveExitCode: %b", ev.Have)
	}
	if ev.Have.Has(HaveCommandLine) {
		t.Errorf("4689 must never claim CommandLine — it isn't in the event")
	}
}

func TestParseWindowsProcessEventXML_UnrecognizedEventIDIgnored(t *testing.T) {
	const other = `<Event><System><EventID>4624</EventID><TimeCreated SystemTime="2026-07-29T10:00:00Z"/></System><EventData></EventData></Event>`
	if _, ok := parseWindowsProcessEventXML(other); ok {
		t.Error("expected ok=false for a non-4688/4689 event")
	}
}

func TestParseWindowsProcessEventXML_MalformedXML(t *testing.T) {
	if _, ok := parseWindowsProcessEventXML("not xml at all"); ok {
		t.Error("expected ok=false for malformed XML")
	}
}

func TestParseTokenElevationType(t *testing.T) {
	cases := []struct {
		name string
		xml  string
		want epm.Tri
	}{
		{"full/elevated", `<Event><System><EventID>4688</EventID></System><EventData><Data Name="TokenElevationType">%%1937</Data></EventData></Event>`, epm.TriTrue},
		{"limited/filtered", `<Event><System><EventID>4688</EventID></System><EventData><Data Name="TokenElevationType">%%1938</Data></EventData></Event>`, epm.TriFalse},
		{"default/ambiguous", `<Event><System><EventID>4688</EventID></System><EventData><Data Name="TokenElevationType">%%1936</Data></EventData></Event>`, epm.TriUnknown},
		{"missing field", `<Event><System><EventID>4688</EventID></System><EventData></EventData></Event>`, epm.TriUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev, ok := parseWindowsProcessEventXML(tc.xml)
			if !ok {
				t.Fatal("parseWindowsProcessEventXML returned ok=false")
			}
			if ev.Elevated != tc.want {
				t.Errorf("Elevated = %v, want %v", ev.Elevated, tc.want)
			}
		})
	}
}
