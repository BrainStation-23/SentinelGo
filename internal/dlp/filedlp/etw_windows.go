//go:build windows && (amd64 || arm64)

package filedlp

// Which program opened which file, from ETW (#331): a real-time session on
// the Microsoft-Windows-Kernel-File provider, CREATE keyword only (one event
// per open, with the opener's PID in the header and the file's NT path in
// the payload). Pure Win32 through advapi32 and tdh; the event callback is a
// Go function (syscall.NewCallback) called on the goroutine's locked thread
// that runs ProcessTrace. ETW is asynchronous: it can't hold anything, and
// under load it drops events (counted), so it only feeds attribution and
// process taint. Needs admin (the service runs as SYSTEM).

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32ETW             = windows.NewLazySystemDLL("advapi32.dll")
	procStartTraceW         = advapi32ETW.NewProc("StartTraceW")
	procControlTraceW       = advapi32ETW.NewProc("ControlTraceW")
	procEnableTraceEx2      = advapi32ETW.NewProc("EnableTraceEx2")
	procOpenTraceW          = advapi32ETW.NewProc("OpenTraceW")
	procProcessTrace        = advapi32ETW.NewProc("ProcessTrace")
	procCloseTrace          = advapi32ETW.NewProc("CloseTrace")
	tdh                     = windows.NewLazySystemDLL("tdh.dll")
	procTdhGetPropertySize  = tdh.NewProc("TdhGetPropertySize")
	procTdhGetProperty      = tdh.NewProc("TdhGetProperty")
	etwCallbackOnce         sync.Once
	etwCallback             uintptr
	etwActive               atomic.Pointer[etwSession] // the session the callback feeds (one at a time)
	kernelFileProvider      = windows.GUID{Data1: 0xedd08927, Data2: 0x9cc4, Data3: 0x4e65, Data4: [8]byte{0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89}}
	etwPropFileName, _      = windows.UTF16PtrFromString("FileName")
	etwPropCreateOptions, _ = windows.UTF16PtrFromString("CreateOptions")
)

const (
	etwSessionName             = "SentinelGo-FileDLP"
	wnodeFlagTracedGUID        = 0x00020000
	eventTraceRealTimeMode     = 0x00000100
	eventTraceControlStop      = 1
	eventControlEnableProvider = 1
	traceLevelInformation      = 4
	kernelFileKeywordCreate    = 0x80
	kernelFileEventCreate      = 12
	processTraceModeRealTime   = 0x00000100
	processTraceModeEventRec   = 0x10000000
	invalidProcessTraceHandle  = ^uint64(0)
	fileDirectoryFile          = 0x00000001 // CreateOptions: FILE_DIRECTORY_FILE
	errorAlreadyExists         = 183
	etwMaxPathBytes            = 2 * 32768 // a long path in UTF-16, with room for the NUL
)

// wnodeHeader is WNODE_HEADER.
type wnodeHeader struct {
	BufferSize        uint32
	ProviderID        uint32
	HistoricalContext uint64
	TimeStamp         int64
	GUID              windows.GUID
	ClientContext     uint32
	Flags             uint32
}

// eventTraceProperties is EVENT_TRACE_PROPERTIES.
type eventTraceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadID      windows.Handle
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

// eventTraceHeader is EVENT_TRACE_HEADER; only its size matters here.
type eventTraceHeader struct {
	Size          uint16
	FieldTypeFlag uint16
	Version       uint32
	ThreadID      uint32
	ProcessID     uint32
	TimeStamp     int64
	GUID          windows.GUID
	ProcessorTime uint64
}

// eventTrace is EVENT_TRACE.
type eventTrace struct {
	Header           eventTraceHeader
	InstanceID       uint32
	ParentInstanceID uint32
	ParentGUID       windows.GUID
	MofData          uintptr
	MofLength        uint32
	ClientContext    uint32
}

// timeZoneInformation is TIME_ZONE_INFORMATION.
type timeZoneInformation struct {
	Bias         int32
	StandardName [32]uint16
	StandardDate windows.Systemtime
	StandardBias int32
	DaylightName [32]uint16
	DaylightDate windows.Systemtime
	DaylightBias int32
}

// traceLogfileHeader is TRACE_LOGFILE_HEADER.
type traceLogfileHeader struct {
	BufferSize         uint32
	Version            uint32
	ProviderVersion    uint32
	NumberOfProcessors uint32
	EndTime            int64
	TimerResolution    uint32
	MaximumFileSize    uint32
	LogFileMode        uint32
	BuffersWritten     uint32
	LogInstanceGUID    windows.GUID
	LoggerName         uintptr
	LogFileName        uintptr
	TimeZone           timeZoneInformation
	BootTime           int64
	PerfFreq           int64
	StartTime          int64
	ReservedFlags      uint32
	BuffersLost        uint32
}

// eventTraceLogfile is EVENT_TRACE_LOGFILEW.
type eventTraceLogfile struct {
	LogFileName         *uint16
	LoggerName          *uint16
	CurrentTime         int64
	BuffersRead         uint32
	ProcessTraceMode    uint32
	CurrentEvent        eventTrace
	LogfileHeader       traceLogfileHeader
	BufferCallback      uintptr
	BufferSize          uint32
	Filled              uint32
	EventsLost          uint32
	EventRecordCallback uintptr
	IsKernelTrace       uint32
	Context             uintptr
}

// eventRecord is EVENT_RECORD.
type eventRecord struct {
	Header struct {
		Size          uint16
		HeaderType    uint16
		Flags         uint16
		EventProperty uint16
		ThreadID      uint32
		ProcessID     uint32
		TimeStamp     int64
		ProviderID    windows.GUID
		Descriptor    struct {
			ID      uint16
			Version uint8
			Channel uint8
			Level   uint8
			Opcode  uint8
			Task    uint16
			Keyword uint64
		}
		ProcessorTime uint64
		ActivityID    windows.GUID
	}
	BufferContext     uint32
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      uintptr
	UserData          uintptr
	UserContext       uintptr
}

// propertyDataDescriptor is PROPERTY_DATA_DESCRIPTOR.
type propertyDataDescriptor struct {
	PropertyName uint64
	ArrayIndex   uint32
	Reserved     uint32
}

// fileOpen is one open seen by ETW.
type fileOpen struct {
	pid  uint32
	path string // NT path: \Device\HarddiskVolume3\Users\…
}

// etwSession is the running trace.
type etwSession struct {
	session uint64
	trace   uint64
	props   []byte
	onOpen  func(fileOpen)
	self    uint32
	events  atomic.Uint64
	lost    atomic.Uint64
	done    chan struct{}
	buf     []byte // the callback's buffer: it runs on the consumer's thread only
}

// etwAvailable says whether this build can trace (64-bit Windows).
const etwAvailable = true

// startETW starts the session and its consumer; onOpen gets every open of a
// file (not a folder) by a process other than this one. Only one session
// runs at a time.
func startETW(onOpen func(fileOpen)) (*etwSession, error) {
	etwCallbackOnce.Do(func() { etwCallback = windows.NewCallback(etwEventCallback) })
	s := &etwSession{onOpen: onOpen, self: windows.GetCurrentProcessId(), done: make(chan struct{}), buf: make([]byte, etwMaxPathBytes)}
	if !etwActive.CompareAndSwap(nil, s) {
		return nil, errors.New("a file trace is already running")
	}
	name, _ := windows.UTF16FromString(etwSessionName)
	props := func() *eventTraceProperties {
		s.props = make([]byte, int(unsafe.Sizeof(eventTraceProperties{}))+len(name)*2+16)
		p := (*eventTraceProperties)(unsafe.Pointer(&s.props[0]))
		p.Wnode.BufferSize = uint32(len(s.props))
		p.Wnode.Flags = wnodeFlagTracedGUID
		p.Wnode.ClientContext = 1 // QPC timestamps
		p.LogFileMode = eventTraceRealTimeMode
		p.LoggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))
		return p
	}
	namep := &name[0]
	r, _, _ := procStartTraceW.Call(uintptr(unsafe.Pointer(&s.session)), uintptr(unsafe.Pointer(namep)), uintptr(unsafe.Pointer(props())))
	if r == errorAlreadyExists {
		// Left over from a crashed agent: stop it and start ours.
		_, _, _ = procControlTraceW.Call(0, uintptr(unsafe.Pointer(namep)), uintptr(unsafe.Pointer(props())), eventTraceControlStop)
		r, _, _ = procStartTraceW.Call(uintptr(unsafe.Pointer(&s.session)), uintptr(unsafe.Pointer(namep)), uintptr(unsafe.Pointer(props())))
	}
	if r != 0 {
		etwActive.Store(nil)
		return nil, fmt.Errorf("StartTrace: %w", windows.Errno(r))
	}
	r, _, _ = procEnableTraceEx2.Call(uintptr(s.session), uintptr(unsafe.Pointer(&kernelFileProvider)), eventControlEnableProvider,
		traceLevelInformation, kernelFileKeywordCreate, 0, 0, 0)
	if r != 0 {
		s.stopSession()
		etwActive.Store(nil)
		return nil, fmt.Errorf("EnableTraceEx2: %w", windows.Errno(r))
	}
	ready := make(chan error, 1)
	go s.consume(namep, ready)
	if err := <-ready; err != nil {
		s.stopSession()
		<-s.done
		etwActive.Store(nil)
		return nil, err
	}
	return s, nil
}

// consume opens the real-time trace and runs ProcessTrace until the
// session stops. The callback runs on this goroutine's locked thread.
func (s *etwSession) consume(name *uint16, ready chan<- error) {
	defer close(s.done)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	lf := eventTraceLogfile{LoggerName: name, ProcessTraceMode: processTraceModeRealTime | processTraceModeEventRec, EventRecordCallback: etwCallback}
	h, _, err := procOpenTraceW.Call(uintptr(unsafe.Pointer(&lf)))
	if uint64(h) == invalidProcessTraceHandle {
		ready <- fmt.Errorf("OpenTrace: %w", err)
		return
	}
	s.trace = uint64(h)
	ready <- nil
	handles := [1]uint64{s.trace}
	_, _, _ = procProcessTrace.Call(uintptr(unsafe.Pointer(&handles[0])), 1, 0, 0) // returns when the session stops
	_, _, _ = procCloseTrace.Call(uintptr(s.trace))
}

// stop ends the session and waits for the consumer.
func (s *etwSession) stop() {
	s.stopSession()
	<-s.done
	etwActive.CompareAndSwap(s, nil)
}

func (s *etwSession) stopSession() {
	if len(s.props) == 0 {
		return
	}
	p := (*eventTraceProperties)(unsafe.Pointer(&s.props[0]))
	p.LoggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))
	_, _, _ = procControlTraceW.Call(uintptr(s.session), 0, uintptr(unsafe.Pointer(p)), eventTraceControlStop)
	s.lost.Add(uint64(p.EventsLost) + uint64(p.RealTimeBuffersLost))
}

// stats is how many opens were seen and lost.
func (s *etwSession) stats() (events, lost uint64) { return s.events.Load(), s.lost.Load() }

// etwEventCallback is EventRecordCallback.
func etwEventCallback(r *eventRecord) uintptr {
	s := etwActive.Load()
	if s == nil || r.Header.Descriptor.ID != kernelFileEventCreate || r.Header.ProviderID != kernelFileProvider || r.Header.ProcessID == s.self {
		return 0
	}
	s.events.Add(1)
	if opts, ok := etwUint32(r, etwPropCreateOptions); ok && opts&fileDirectoryFile != 0 {
		return 0
	}
	if path := etwString(r, etwPropFileName, s.buf); path != "" {
		s.onOpen(fileOpen{pid: r.Header.ProcessID, path: path})
	}
	return 0
}

// etwProperty reads one top-level property of r through TDH.
func etwProperty(r *eventRecord, name *uint16, buf []byte) (int, bool) {
	d := propertyDataDescriptor{PropertyName: uint64(uintptr(unsafe.Pointer(name))), ArrayIndex: 0xFFFFFFFF}
	var size uint32
	if rc, _, _ := procTdhGetPropertySize.Call(uintptr(unsafe.Pointer(r)), 0, 0, 1, uintptr(unsafe.Pointer(&d)), uintptr(unsafe.Pointer(&size))); rc != 0 {
		return 0, false
	}
	if size == 0 || int(size) > len(buf) {
		return 0, false
	}
	if rc, _, _ := procTdhGetProperty.Call(uintptr(unsafe.Pointer(r)), 0, 0, 1, uintptr(unsafe.Pointer(&d)), uintptr(size), uintptr(unsafe.Pointer(&buf[0]))); rc != 0 {
		return 0, false
	}
	return int(size), true
}

func etwUint32(r *eventRecord, name *uint16) (uint32, bool) {
	var b [4]byte
	n, ok := etwProperty(r, name, b[:])
	if !ok || n != 4 {
		return 0, false
	}
	return le32(b[:]), true
}

func etwString(r *eventRecord, name *uint16, buf []byte) string {
	n, ok := etwProperty(r, name, buf)
	if !ok || n < 2 {
		return ""
	}
	u := make([]uint16, n/2)
	for i := range u {
		u[i] = uint16(buf[2*i]) | uint16(buf[2*i+1])<<8
	}
	return windows.UTF16ToString(u)
}
