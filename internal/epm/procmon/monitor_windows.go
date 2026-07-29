//go:build windows

package procmon

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows Event Log API — a self-contained wevtapi.dll binding, deliberately
// not shared with internal/auditlogs/collector's own copy: that package
// collects a broad set of channels for the audit-upload pipeline, this one
// subscribes to exactly two Security-channel event IDs for a structurally
// different purpose (live process telemetry, not log shipping), and the two
// call sites' lifetimes/error handling do not otherwise overlap. This is
// ordinary platform-API-binding duplication, not the kind of
// triplicated-business-logic duplication Phase 2 eliminated from the
// pipe/socket transports.
const (
	evtSubscribeToFutureEvents = 1
	evtRenderEventXML          = 1
)

var (
	modWevtapi = windows.NewLazySystemDLL("wevtapi.dll")

	procEvtSubscribe = modWevtapi.NewProc("EvtSubscribe")
	procEvtNext      = modWevtapi.NewProc("EvtNext")
	procEvtRender    = modWevtapi.NewProc("EvtRender")
	procEvtClose     = modWevtapi.NewProc("EvtClose")
)

// process4688Query subscribes to process creation (4688) and process
// termination (4689) only. Command line is only populated by 4688 when
// "Audit Process Creation" + "Include command line in process creation
// events" are both enabled via policy — when they are not, CommandLine
// simply stays empty and HaveCommandLine is unset, the same
// graceful-when-unavailable handling used throughout this backend.
const process4688Query = "*[System[(EventID=4688 or EventID=4689)]]"

const windowsEventBufferSize = 1024

// windowsMonitor subscribes to the Security event log's process
// creation/termination events via EvtSubscribe. See collector_windows.go
// (internal/auditlogs/collector) for the same signal-event + WaitForSingleObject
// pattern used here, chosen over a true EvtSubscribe callback because it
// keeps the event loop on a single, ordinary Go goroutine rather than an
// OS-invoked callback thread, which is both simpler to reason about and
// consistent with the rest of this codebase.
type windowsMonitor struct {
	bus    *eventBus
	handle uintptr
	signal windows.Handle
	cancel chan struct{}
	done   chan struct{}
}

// New returns the Windows process monitor.
func New() Monitor {
	return &windowsMonitor{bus: newEventBus(windowsEventBufferSize)}
}

func (m *windowsMonitor) Start() error {
	channelPath, err := windows.UTF16PtrFromString("Security")
	if err != nil {
		return fmt.Errorf("procmon: UTF16 channel path: %w", err)
	}
	query, err := windows.UTF16PtrFromString(process4688Query)
	if err != nil {
		return fmt.Errorf("procmon: UTF16 query: %w", err)
	}

	signal, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return fmt.Errorf("procmon: CreateEvent: %w", err)
	}

	handle, _, callErr := procEvtSubscribe.Call(
		0,
		uintptr(signal),
		uintptr(unsafe.Pointer(channelPath)),
		uintptr(unsafe.Pointer(query)),
		0,
		0,
		0,
		evtSubscribeToFutureEvents,
	)
	if handle == 0 {
		_ = windows.CloseHandle(signal)
		return fmt.Errorf("procmon: EvtSubscribe: %w", callErr)
	}

	m.handle = handle
	m.signal = signal
	m.cancel = make(chan struct{})
	m.done = make(chan struct{})
	go m.loop()
	return nil
}

func (m *windowsMonitor) loop() {
	defer close(m.done)
	renderBuf := make([]uint16, 64*1024)

	for {
		select {
		case <-m.cancel:
			return
		default:
		}

		event, err := windows.WaitForSingleObject(m.signal, 1000)
		if err != nil {
			return
		}
		if event != windows.WAIT_OBJECT_0 {
			continue // timeout; loop back to check cancel
		}

		for _, ev := range readWindowsProcessEvents(m.handle, renderBuf) {
			m.bus.send(ev)
		}
	}
}

func (m *windowsMonitor) Events() <-chan ProcessEvent { return m.bus.Events() }

func (m *windowsMonitor) Dropped() uint64 { return m.bus.Dropped() }

func (m *windowsMonitor) Stop() {
	if m.cancel == nil {
		return
	}
	close(m.cancel)
	<-m.done
	_, _, _ = procEvtClose.Call(m.handle)
	_ = windows.CloseHandle(m.signal)
	m.bus.close()
}

// readWindowsProcessEvents drains every event currently available on handle
// (an EvtSubscribe result set) and parses each into a ProcessEvent.
func readWindowsProcessEvents(handle uintptr, renderBuf []uint16) []ProcessEvent {
	var events []ProcessEvent
	eventHandles := make([]uintptr, 64)

	for {
		var returned uint32
		ret, _, _ := procEvtNext.Call(
			handle,
			uintptr(len(eventHandles)),
			uintptr(unsafe.Pointer(&eventHandles[0])),
			0, // don't block: we already know events are available
			0,
			uintptr(unsafe.Pointer(&returned)),
		)
		if ret == 0 || returned == 0 {
			break
		}

		for i := uint32(0); i < returned; i++ {
			if xmlStr, ok := renderWindowsEvent(eventHandles[i], renderBuf); ok {
				if ev, ok := parseWindowsProcessEventXML(xmlStr); ok {
					events = append(events, ev)
				}
			}
			_, _, _ = procEvtClose.Call(eventHandles[i])
		}

		if len(events) >= 1000 {
			break
		}
	}
	return events
}

func renderWindowsEvent(evtHandle uintptr, buf []uint16) (string, bool) {
	var bufUsed, propertyCount uint32
	ret, _, _ := procEvtRender.Call(
		0,
		evtHandle,
		evtRenderEventXML,
		uintptr(len(buf)*2),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufUsed)),
		uintptr(unsafe.Pointer(&propertyCount)),
	)
	if ret == 0 {
		return "", false
	}
	return windows.UTF16ToString(buf[:bufUsed/2]), true
}
