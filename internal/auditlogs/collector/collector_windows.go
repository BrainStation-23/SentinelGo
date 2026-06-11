//go:build windows

package collector

import (
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows Event Log API constants
const (
	EvtQueryChannelPath            = 0x1
	EvtQueryForwardDirection       = 0x100
	EvtRenderEventXml              = 1
	EvtSubscribeToFutureEvents     = 1
	EvtSubscribeStartAfterBookmark = 2
)

// Windows Event Log API handles
var (
	modWevtapi = windows.NewLazySystemDLL("wevtapi.dll")

	procEvtQuery     = modWevtapi.NewProc("EvtQuery")
	procEvtNext      = modWevtapi.NewProc("EvtNext")
	procEvtRender    = modWevtapi.NewProc("EvtRender")
	procEvtClose     = modWevtapi.NewProc("EvtClose")
	procEvtSubscribe = modWevtapi.NewProc("EvtSubscribe")
)

// eventChannel defines a Windows Event Log channel to query.
type eventChannel struct {
	name   string // Channel path (e.g. "Security")
	source string // Source name for RawLogEntry
	query  string // XPath query filter
	// cpKey overrides the checkpoint key (source+"_record_id" by default).
	// Set when the same channel is queried multiple times with different filters
	// so each pass tracks its position independently.
	cpKey string
}

// checkpointKey returns the key used to persist this channel's record ID.
func (ch eventChannel) checkpointKey() string {
	if ch.cpKey != "" {
		return ch.cpKey
	}
	return ch.source + "_record_id"
}

// generateSource creates a dynamic source name from channel name
func generateSource(channelName string) string {
	// Convert channel name to lowercase and replace spaces/special chars
	source := strings.ToLower(channelName)
	source = strings.ReplaceAll(source, " ", "_")
	source = strings.ReplaceAll(source, "-", "_")
	source = strings.ReplaceAll(source, "/", "_")

	// Remove consecutive underscores
	for strings.Contains(source, "__") {
		source = strings.ReplaceAll(source, "__", "_")
	}

	// Remove leading/trailing underscores
	source = strings.Trim(source, "_")

	return "windows_" + source
}

// Windows Event Log XPath limits OR conditions to ~22 per expression.
// The Security channel query is split into three groups (≤12 each) to stay
// under that limit, using distinct cpKey values for independent checkpoints.
//
// channels lists the Event Log channels and their XPath filters.
var channels = []eventChannel{
	// Security — group 0: authentication / logon / privilege (5 IDs)
	{
		name:   "Security",
		source: generateSource("Security"),
		cpKey:  generateSource("Security") + "_auth_record_id",
		query:  "*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4648 or EventID=4672)]]",
	},
	// Security — group 1: user / group account management (11 IDs)
	{
		name:   "Security",
		source: generateSource("Security"),
		cpKey:  generateSource("Security") + "_user_record_id",
		query:  "*[System[(EventID=4720 or EventID=4722 or EventID=4723 or EventID=4724 or EventID=4725 or EventID=4726 or EventID=4731 or EventID=4732 or EventID=4733 or EventID=4734 or EventID=4738)]]",
	},
	// Security — group 2: policy, process creation, network, object access (8 IDs)
	{
		name:   "Security",
		source: generateSource("Security"),
		cpKey:  generateSource("Security") + "_policy_record_id",
		query:  "*[System[(EventID=4656 or EventID=4663 or EventID=4670 or EventID=4688 or EventID=4719 or EventID=4739 or EventID=5156 or EventID=5157)]]",
	},
	{
		name:   "System",
		source: generateSource("System"),
		query:  "*[System[(Level=1 or Level=2 or Level=3 or Level=4)]]",
	},
	{
		name:   "System",
		source: generateSource("System_Time_Service"),
		cpKey:  generateSource("System_Time_Service") + "_record_id",
		query:  "*[System[(EventID=35 or EventID=24)]]",
	},
	{
		name:   "Application",
		source: generateSource("Application"),
		query:  "*[System[(Level=1 or Level=2 or Level=3)]]",
	},
	{
		name:   "Microsoft-Windows-Windows Defender/Operational",
		source: generateSource("Microsoft-Windows-Windows Defender/Operational"),
		query:  "*",
	},
	{
		name:   "Microsoft-Windows-PowerShell/Operational",
		source: generateSource("Microsoft-Windows-PowerShell/Operational"),
		query:  "*[System[(EventID=4103 or EventID=4104 or EventID=4105 or EventID=4106)]]",
	},
	{
		name:   "Microsoft-Windows-TaskScheduler/Operational",
		source: generateSource("Microsoft-Windows-TaskScheduler/Operational"),
		query:  "*[System[(EventID=100 or EventID=102 or EventID=103 or EventID=106 or EventID=141 or EventID=200 or EventID=201)]]",
	},
	{
		name:   "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
		source: generateSource("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"),
		query:  "*[System[(Level=1 or Level=2 or Level=3)]]",
	},
	{
		name:   "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
		source: generateSource("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"),
		query:  "*[System[(EventID=1149 or EventID=261 or EventID=1158)]]",
	},
	{
		name:   "Microsoft-Windows-GroupPolicy/Operational",
		source: generateSource("Microsoft-Windows-GroupPolicy/Operational"),
		query:  "*[System[(Level=1 or Level=2 or Level=3)]]",
	},
}

// eventXML represents the XML structure of a rendered Windows event.
type eventXML struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     int `xml:"EventID"`
		Level       int `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		EventRecordID int64  `xml:"EventRecordID"`
		Channel       string `xml:"Channel"`
		Computer      string `xml:"Computer"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

type windowsCollector struct{}

// NewCollector creates a Windows-specific log collector using
// the Windows Event Log API (EvtQuery, EvtSubscribe, EvtNext, EvtRender).
func NewCollector() Collector {
	return &windowsCollector{}
}

// Sources returns the list of Windows Event Log channels being collected.
func (c *windowsCollector) Sources() []string {
	sources := make([]string, len(channels))
	for i, ch := range channels {
		sources[i] = ch.source
	}
	return sources
}

// Collect performs batch queries across all configured event log channels.
func (c *windowsCollector) Collect(ctx context.Context, checkpoint CheckpointData) ([]RawLogEntry, CheckpointData, error) {
	if checkpoint == nil {
		checkpoint = make(CheckpointData)
	}

	newCP := make(CheckpointData)
	for k, v := range checkpoint {
		newCP[k] = v
	}

	var allEntries []RawLogEntry

	for _, ch := range channels {
		if ctx.Err() != nil {
			break
		}

		entries, lastRecordID, err := c.queryChannel(ctx, ch, checkpoint)
		if err != nil {
			log.Printf("[collector/windows] channel %s error: %v", ch.name, err)
			continue
		}

		allEntries = append(allEntries, entries...)
		if lastRecordID > 0 {
			newCP[ch.checkpointKey()] = lastRecordID
		}
	}

	return allEntries, newCP, nil
}

// securityRealTimeQuery is the XPath filter used for real-time Security channel
// subscription. It covers the most operationally significant auth events and stays
// well under the Windows XPath OR-condition limit (~22).
const securityRealTimeQuery = "*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4648 or EventID=4672 or EventID=4688 or EventID=4720 or EventID=4725 or EventID=4726 or EventID=5156 or EventID=5157)]]"

// Subscribe starts real-time subscription on the Security channel.
func (c *windowsCollector) Subscribe(ctx context.Context, ch chan<- RawLogEntry) error {
	channelPath, err := windows.UTF16PtrFromString("Security")
	if err != nil {
		return fmt.Errorf("UTF16 channel path: %w", err)
	}

	query, err := windows.UTF16PtrFromString(securityRealTimeQuery)
	if err != nil {
		return fmt.Errorf("UTF16 query: %w", err)
	}

	// Create a signal event for notifications
	signalEvent, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return fmt.Errorf("CreateEvent: %w", err)
	}
	defer func() { _ = windows.CloseHandle(signalEvent) }()

	// EvtSubscribe(Session, SignalEvent, ChannelPath, Query, Bookmark, Context, Callback, Flags)
	handle, _, callErr := procEvtSubscribe.Call(
		0,                                    // Session (local)
		uintptr(signalEvent),                 // SignalEvent
		uintptr(unsafe.Pointer(channelPath)), // ChannelPath
		uintptr(unsafe.Pointer(query)),       // Query
		0,                                    // Bookmark
		0,                                    // Context
		0,                                    // Callback (using signal event instead)
		EvtSubscribeToFutureEvents,           // Flags
	)
	if handle == 0 {
		return fmt.Errorf("EvtSubscribe failed: %v", callErr)
	}
	defer func() { _, _, _ = procEvtClose.Call(handle) }()

	renderBuf := make([]uint16, 64*1024)

	for {
		if ctx.Err() != nil {
			return nil
		}

		// Wait for events (1 second timeout)
		event, err := windows.WaitForSingleObject(signalEvent, 1000)
		if err != nil {
			return fmt.Errorf("WaitForSingleObject: %w", err)
		}

		if event != windows.WAIT_OBJECT_0 {
			continue // Timeout, check context and loop
		}

		// Read available events
		entries := c.readEvents(handle, renderBuf, "windows_security")
		for _, entry := range entries {
			select {
			case ch <- entry:
			case <-ctx.Done():
				return nil
			default:
				// Channel full, drop
			}
		}
	}
}

// buildXPathQuery combines the channel's base XPath filter with a record ID lower bound.
func buildXPathQuery(baseQuery string, rid int64) string {
	if baseQuery == "*" {
		return fmt.Sprintf("*[System[EventRecordID > %d]]", rid)
	}
	inner := strings.TrimPrefix(baseQuery, "*[System[")
	inner = strings.TrimSuffix(inner, "]]")
	return fmt.Sprintf("*[System[EventRecordID > %d and (%s)]]", rid, inner)
}

// queryChannel queries a single event log channel from the checkpoint position.
func (c *windowsCollector) queryChannel(ctx context.Context, ch eventChannel, checkpoint CheckpointData) ([]RawLogEntry, int64, error) {
	if ctx.Err() != nil {
		return nil, 0, ctx.Err()
	}

	query := ch.query
	// Tolerant accessor: the checkpoint value is an in-memory int64 between
	// cycles and a float64 after JSON persistence. A bare .(float64) assertion
	// panicked on the in-memory int64 path and crashed the agent.
	if rid, ok := CheckpointInt64(checkpoint, ch.checkpointKey()); ok && rid > 0 {
		query = buildXPathQuery(ch.query, rid)
	}

	channelPath, err := windows.UTF16PtrFromString(ch.name)
	if err != nil {
		return nil, 0, err
	}

	queryStr, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return nil, 0, err
	}

	// EvtQuery(Session, Path, Query, Flags)
	handle, _, callErr := procEvtQuery.Call(
		0, // Session (local)
		uintptr(unsafe.Pointer(channelPath)),
		uintptr(unsafe.Pointer(queryStr)),
		EvtQueryChannelPath|EvtQueryForwardDirection,
	)
	if handle == 0 {
		return nil, 0, fmt.Errorf("EvtQuery on %s: %v", ch.name, callErr)
	}
	defer func() { _, _, _ = procEvtClose.Call(handle) }()

	renderBuf := make([]uint16, 64*1024)
	entries := c.readEvents(handle, renderBuf, ch.source)

	var lastRecordID int64
	if len(entries) > 0 {
		if rid, ok := entries[len(entries)-1].Metadata["record_id"]; ok {
			if n, scanErr := fmt.Sscanf(rid, "%d", &lastRecordID); scanErr != nil || n != 1 {
				log.Printf("[collector/windows] failed to parse record_id %q: %v", rid, scanErr)
				lastRecordID = 0
			}
		}
	}

	return entries, lastRecordID, nil
}

// readEvents reads and renders events from an event query/subscription handle.
func (c *windowsCollector) readEvents(handle uintptr, renderBuf []uint16, source string) []RawLogEntry {
	var entries []RawLogEntry
	eventHandles := make([]uintptr, 64)

	for {
		var returned uint32

		// EvtNext(ResultSet, EventsSize, Events, Timeout, Flags, Returned)
		ret, _, _ := procEvtNext.Call(
			handle,
			uintptr(len(eventHandles)),
			uintptr(unsafe.Pointer(&eventHandles[0])),
			1000, // 1 second timeout
			0,    // Flags
			uintptr(unsafe.Pointer(&returned)),
		)
		if ret == 0 || returned == 0 {
			break
		}

		for i := uint32(0); i < returned; i++ {
			evtHandle := eventHandles[i]
			entry := c.renderEvent(evtHandle, renderBuf, source)
			if entry != nil {
				entries = append(entries, *entry)
			}
			_, _, _ = procEvtClose.Call(evtHandle)
		}

		if len(entries) >= 1000 {
			break
		}
	}

	return entries
}

// renderEvent renders a single event handle to XML and parses it.
func (c *windowsCollector) renderEvent(evtHandle uintptr, buf []uint16, source string) *RawLogEntry {
	var bufUsed, propertyCount uint32

	// EvtRender(Context, Fragment, Flags, BufferSize, Buffer, BufferUsed, PropertyCount)
	ret, _, _ := procEvtRender.Call(
		0, // Context
		evtHandle,
		EvtRenderEventXml,
		uintptr(len(buf)*2), // size in bytes
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufUsed)),
		uintptr(unsafe.Pointer(&propertyCount)),
	)
	if ret == 0 {
		return nil
	}

	// Convert UTF-16 to string
	xmlStr := windows.UTF16ToString(buf[:bufUsed/2])

	// Parse XML
	var evt eventXML
	if err := xml.Unmarshal([]byte(xmlStr), &evt); err != nil {
		return nil
	}

	// Build entry
	entry := &RawLogEntry{
		Source:   source,
		EventID:  fmt.Sprintf("%d", evt.System.EventID),
		Severity: windowsLevelToSeverity(evt.System.Level),
		Metadata: make(map[string]string),
	}

	// Parse timestamp
	if t, err := time.Parse(time.RFC3339Nano, evt.System.TimeCreated.SystemTime); err == nil {
		entry.Timestamp = t
	} else {
		entry.Timestamp = time.Now()
	}

	// Set metadata
	entry.Metadata["provider"] = evt.System.Provider.Name
	entry.Metadata["channel"] = evt.System.Channel
	entry.Metadata["computer"] = evt.System.Computer
	entry.Metadata["record_id"] = fmt.Sprintf("%d", evt.System.EventRecordID)

	// Extract EventData fields
	var msgParts []string
	for _, d := range evt.EventData.Data {
		if d.Name != "" {
			entry.Metadata[d.Name] = d.Value
		}
		if d.Value != "" {
			msgParts = append(msgParts, d.Value)
		}
	}
	entry.RawMessage = strings.Join(msgParts, " | ")

	return entry
}

// windowsLevelToSeverity maps Windows event level to syslog-style severity string.
func windowsLevelToSeverity(level int) string {
	switch level {
	case 1: // Critical
		return "2"
	case 2: // Error
		return "3"
	case 3: // Warning
		return "4"
	case 4: // Information
		return "6"
	case 5: // Verbose
		return "7"
	default:
		return "6"
	}
}
