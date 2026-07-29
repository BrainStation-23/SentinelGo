//go:build windows

package procmon

import (
	"encoding/xml"
	"strconv"
	"time"

	"sentinelgo/internal/epm"
)

// windowsEventXML is the minimal System+EventData shape shared by 4688
// (process creation) and 4689 (process termination), rendered by
// EvtRender(EvtRenderEventXml). Split out from monitor_windows.go and kept
// dependency-free (pure parsing, no Windows API calls) specifically so it is
// unit-testable against committed fixture strings without a live event
// subscription — the same reasoning the plan applies to ETW decoding
// generally: "pure decode functions over committed byte fixtures; live
// session behind !testing.Short()".
type windowsEventXML struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		EventID     int `xml:"EventID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

func (e *windowsEventXML) field(name string) (string, bool) {
	for _, d := range e.EventData.Data {
		if d.Name == name {
			return d.Value, d.Value != ""
		}
	}
	return "", false
}

// parseWindowsProcessEventXML parses one rendered 4688/4689 event. Returns
// ok=false for any other event ID (should not occur given process4688Query,
// but defensive against a future query change) or malformed XML.
func parseWindowsProcessEventXML(raw string) (ProcessEvent, bool) {
	var evt windowsEventXML
	if err := xml.Unmarshal([]byte(raw), &evt); err != nil {
		return ProcessEvent{}, false
	}

	observedAt := time.Now().UTC()
	if t, err := time.Parse(time.RFC3339Nano, evt.System.TimeCreated.SystemTime); err == nil {
		observedAt = t.UTC()
	}

	switch evt.System.EventID {
	case 4688:
		return parse4688(&evt, observedAt)
	case 4689:
		return parse4689(&evt, observedAt)
	default:
		return ProcessEvent{}, false
	}
}

func parse4688(evt *windowsEventXML, observedAt time.Time) (ProcessEvent, bool) {
	ev := ProcessEvent{Kind: EventStart, ObservedAt: observedAt, Source: "etw4688", Have: HavePID}

	if pidHex, ok := evt.field("NewProcessId"); ok {
		if pid, err := strconv.ParseInt(pidHex, 0, 64); err == nil {
			ev.PID = int(pid)
		}
	}
	if ppidHex, ok := evt.field("ProcessId"); ok {
		if ppid, err := strconv.ParseInt(ppidHex, 0, 64); err == nil {
			ev.ParentPID = int(ppid)
			ev.Have |= HaveParentPID
		}
	}
	if name, ok := evt.field("NewProcessName"); ok {
		ev.ImagePath = name
		ev.Have |= HaveImagePath
	}
	if cmd, ok := evt.field("CommandLine"); ok {
		ev.CommandLine = cmd
		ev.Have |= HaveCommandLine
	}
	if uid, ok := evt.field("SubjectUserSid"); ok {
		ev.UserID = uid
		ev.Have |= HaveUserID
	}
	ev.Elevated = parseTokenElevationType(evt)
	if ev.Elevated != epm.TriUnknown {
		ev.Have |= HaveElevated
	}
	return ev, true
}

func parse4689(evt *windowsEventXML, observedAt time.Time) (ProcessEvent, bool) {
	ev := ProcessEvent{Kind: EventExit, ObservedAt: observedAt, Source: "etw4688", Have: HavePID}

	if pidHex, ok := evt.field("ProcessId"); ok {
		if pid, err := strconv.ParseInt(pidHex, 0, 64); err == nil {
			ev.PID = int(pid)
		}
	}
	if name, ok := evt.field("ProcessName"); ok {
		ev.ImagePath = name
		ev.Have |= HaveImagePath
	}
	if uid, ok := evt.field("SubjectUserSid"); ok {
		ev.UserID = uid
		ev.Have |= HaveUserID
	}
	if statusHex, ok := evt.field("Status"); ok {
		if code, err := strconv.ParseInt(statusHex, 0, 64); err == nil {
			ev.ExitCode = int(code)
			ev.Have |= HaveExitCode
		}
	}
	ev.Elevated = epm.TriUnknown
	return ev, true
}

// parseTokenElevationType maps 4688's TokenElevationType field — a raw,
// unresolved "%%NNNN" message-table reference, since EvtRenderEventXml does
// not resolve them (that needs the heavier EvtFormatMessage call, not used
// here) — to a Tri. %%1937 is TokenElevationTypeFull (a split UAC token
// actually running elevated): the only value this treats as a confident
// TriTrue. %%1938 (TokenElevationTypeLimited, a split token's filtered,
// non-elevated half) is a confident TriFalse. %%1936
// (TokenElevationTypeDefault — no UAC split in play at all, e.g. UAC
// disabled or a non-split-token account) is deliberately TriUnknown rather
// than assumed non-elevated: a non-split built-in Administrator account
// reports Default while still running with full privileges, so guessing
// False here would be a false negative on that account type.
func parseTokenElevationType(evt *windowsEventXML) epm.Tri {
	v, ok := evt.field("TokenElevationType")
	if !ok {
		return epm.TriUnknown
	}
	switch v {
	case "%%1937":
		return epm.TriTrue
	case "%%1938":
		return epm.TriFalse
	default:
		return epm.TriUnknown
	}
}
