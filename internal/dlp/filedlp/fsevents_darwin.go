package filedlp

// FSEvents for macOS file DLP (#332, layer 1): one stream per watched
// volume, file-level events, delivered on a serial dispatch queue. Reached
// through purego (no cgo). The C callback is one Go function for every
// stream; it finds its stream by the id passed as the context's info (never
// a Go pointer), copies the paths into Go strings and returns: no scanning,
// no locks held across calls into the OS. A stream holds no descriptor on
// the volume, so it doesn't stop the user from ejecting it.

import (
	"fmt"
	"strings"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

const (
	fseCreateFlagNoDefer    = 0x00000002
	fseCreateFlagIgnoreSelf = 0x00000008
	fseCreateFlagFileEvents = 0x00000010
	fseSinceNow             = ^uint64(0)
	fseLatency              = 0.5 // seconds

	fseMustScanSubDirs = 0x00000001
	fseUserDropped     = 0x00000002
	fseKernelDropped   = 0x00000004
	fseRootChanged     = 0x00000020
	fseUnmount         = 0x00000080
	fseItemCreated     = 0x00000100
	fseItemRenamed     = 0x00000800
	fseItemModified    = 0x00001000
	fseItemIsFile      = 0x00010000

	cfStringEncodingUTF8 = 0x08000100
)

// fseContext is FSEventStreamContext.
type fseContext struct {
	Version         int
	Info            uintptr
	Retain          uintptr
	Release         uintptr
	CopyDescription uintptr
}

var (
	fseOnce sync.Once
	fseErr  error

	fsEventStreamCreate           func(alloc, cb uintptr, ctx *fseContext, paths uintptr, since uint64, latency float64, flags uint32) uintptr
	fsEventStreamSetDispatchQueue func(stream, queue uintptr)
	fsEventStreamStart            func(stream uintptr) bool
	fsEventStreamStop             func(stream uintptr)
	fsEventStreamInvalidate       func(stream uintptr)
	fsEventStreamRelease          func(stream uintptr)
	cfStringCreateWithCString     func(alloc uintptr, s string, enc uint32) uintptr
	cfArrayCreate                 func(alloc uintptr, values unsafe.Pointer, n int, callbacks uintptr) uintptr
	cfRelease                     func(obj uintptr)
	dispatchQueueCreate           func(label string, attr uintptr) uintptr
	cfTypeArrayCallBacks          uintptr
	fseCallback                   uintptr

	fseMu      sync.Mutex
	fseStreams = map[uintptr]*fseStream{}
	fseNextID  uintptr
)

func loadFSEvents() error {
	fseOnce.Do(func() {
		cs, err := purego.Dlopen("/System/Library/Frameworks/CoreServices.framework/CoreServices", purego.RTLD_GLOBAL|purego.RTLD_NOW)
		if err != nil {
			fseErr = fmt.Errorf("load CoreServices: %w", err)
			return
		}
		cf, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_GLOBAL|purego.RTLD_NOW)
		if err != nil {
			fseErr = fmt.Errorf("load CoreFoundation: %w", err)
			return
		}
		sys, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_GLOBAL|purego.RTLD_NOW)
		if err != nil {
			fseErr = fmt.Errorf("load libSystem: %w", err)
			return
		}
		purego.RegisterLibFunc(&fsEventStreamCreate, cs, "FSEventStreamCreate")
		purego.RegisterLibFunc(&fsEventStreamSetDispatchQueue, cs, "FSEventStreamSetDispatchQueue")
		purego.RegisterLibFunc(&fsEventStreamStart, cs, "FSEventStreamStart")
		purego.RegisterLibFunc(&fsEventStreamStop, cs, "FSEventStreamStop")
		purego.RegisterLibFunc(&fsEventStreamInvalidate, cs, "FSEventStreamInvalidate")
		purego.RegisterLibFunc(&fsEventStreamRelease, cs, "FSEventStreamRelease")
		purego.RegisterLibFunc(&cfStringCreateWithCString, cf, "CFStringCreateWithCString")
		purego.RegisterLibFunc(&cfArrayCreate, cf, "CFArrayCreate")
		purego.RegisterLibFunc(&cfRelease, cf, "CFRelease")
		purego.RegisterLibFunc(&dispatchQueueCreate, sys, "dispatch_queue_create")
		cfTypeArrayCallBacks, err = purego.Dlsym(cf, "kCFTypeArrayCallBacks")
		if err != nil {
			fseErr = fmt.Errorf("kCFTypeArrayCallBacks: %w", err)
			return
		}
		fseCallback = purego.NewCallback(fseEventCallback)
	})
	return fseErr
}

// fseStream is a running stream on one root.
type fseStream struct {
	id       uintptr
	root     string
	stream   uintptr
	change   func(fsChange)
	overflow func(root string)
	gone     func(root string)
	closed   sync.Once
}

// fseQueue is the serial queue every stream delivers on (one, so the
// callbacks never run concurrently).
var (
	fseQueueOnce sync.Once
	fseQueue     uintptr
)

// startFSEvents watches root (recursively) for files created, modified or
// renamed into place by other processes.
func startFSEvents(root string, change func(fsChange), overflow func(root string), gone func(root string)) (*fseStream, error) {
	if err := loadFSEvents(); err != nil {
		return nil, err
	}
	fseQueueOnce.Do(func() { fseQueue = dispatchQueueCreate("com.sentinelgo.filedlp.fsevents", 0) })
	if fseQueue == 0 {
		return nil, fmt.Errorf("dispatch_queue_create failed")
	}
	path := cfStringCreateWithCString(0, root, cfStringEncodingUTF8)
	if path == 0 {
		return nil, fmt.Errorf("CFStringCreateWithCString failed")
	}
	defer cfRelease(path)
	values := [1]uintptr{path}
	paths := cfArrayCreate(0, unsafe.Pointer(&values[0]), 1, cfTypeArrayCallBacks)
	if paths == 0 {
		return nil, fmt.Errorf("CFArrayCreate failed")
	}
	defer cfRelease(paths)

	fseMu.Lock()
	fseNextID++
	s := &fseStream{id: fseNextID, root: strings.TrimSuffix(root, "/") + "/", change: change, overflow: overflow, gone: gone}
	fseStreams[s.id] = s
	fseMu.Unlock()

	ctx := fseContext{Info: s.id}
	s.stream = fsEventStreamCreate(0, fseCallback, &ctx, paths, fseSinceNow, fseLatency,
		fseCreateFlagNoDefer|fseCreateFlagFileEvents|fseCreateFlagIgnoreSelf)
	if s.stream == 0 {
		s.forget()
		return nil, fmt.Errorf("FSEventStreamCreate failed")
	}
	fsEventStreamSetDispatchQueue(s.stream, fseQueue)
	if !fsEventStreamStart(s.stream) {
		fsEventStreamInvalidate(s.stream)
		fsEventStreamRelease(s.stream)
		s.forget()
		return nil, fmt.Errorf("FSEventStreamStart failed")
	}
	return s, nil
}

func (s *fseStream) forget() {
	fseMu.Lock()
	delete(fseStreams, s.id)
	fseMu.Unlock()
}

// close stops the stream; no callback for it runs after this returns
// (FSEventStreamInvalidate), and late ones find no stream.
func (s *fseStream) close() {
	s.closed.Do(func() {
		s.forget()
		fsEventStreamStop(s.stream)
		fsEventStreamInvalidate(s.stream)
		fsEventStreamRelease(s.stream)
	})
}

// fseEventCallback is the FSEventStreamCallback for every stream.
func fseEventCallback(_, info, numEvents uintptr, eventPaths, eventFlags unsafe.Pointer, _ uintptr) {
	fseMu.Lock()
	s := fseStreams[info]
	fseMu.Unlock()
	if s == nil || numEvents == 0 || eventPaths == nil || eventFlags == nil {
		return
	}
	n := int(numEvents)
	paths := unsafe.Slice((**byte)(eventPaths), n)
	flags := unsafe.Slice((*uint32)(eventFlags), n)
	for i := 0; i < n; i++ {
		f := flags[i]
		switch {
		case f&(fseMustScanSubDirs|fseUserDropped|fseKernelDropped) != 0:
			s.overflow(s.root)
		case f&(fseUnmount|fseRootChanged) != 0:
			s.gone(s.root)
		case f&fseItemIsFile != 0 && f&(fseItemCreated|fseItemModified|fseItemRenamed) != 0:
			if p := goString(paths[i]); strings.HasPrefix(p, s.root) {
				s.change(fsChange{root: s.root, path: p})
			}
		}
	}
}

// goString copies a NUL-terminated C string.
func goString(p *byte) string {
	if p == nil {
		return ""
	}
	n := 0
	for *(*byte)(unsafe.Add(unsafe.Pointer(p), n)) != 0 {
		n++
		if n > 1<<16 {
			return ""
		}
	}
	return string(unsafe.Slice(p, n))
}
