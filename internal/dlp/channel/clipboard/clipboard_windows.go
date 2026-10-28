//go:build windows

package clipboard

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procRegisterClassExW              = user32.NewProc("RegisterClassExW")
	procCreateWindowExW               = user32.NewProc("CreateWindowExW")
	procDefWindowProcW                = user32.NewProc("DefWindowProcW")
	procGetMessageW                   = user32.NewProc("GetMessageW")
	procDispatchMessageW              = user32.NewProc("DispatchMessageW")
	procPostMessageW                  = user32.NewProc("PostMessageW")
	procDestroyWindow                 = user32.NewProc("DestroyWindow")
	procPostQuitMessage               = user32.NewProc("PostQuitMessage")
	procAddClipboardFormatListener    = user32.NewProc("AddClipboardFormatListener")
	procRemoveClipboardFormatListener = user32.NewProc("RemoveClipboardFormatListener")
	procOpenClipboard                 = user32.NewProc("OpenClipboard")
	procCloseClipboard                = user32.NewProc("CloseClipboard")
	procEmptyClipboard                = user32.NewProc("EmptyClipboard")
	procGetClipboardData              = user32.NewProc("GetClipboardData")
	procSetClipboardData              = user32.NewProc("SetClipboardData")
	procIsClipboardFormatAvailable    = user32.NewProc("IsClipboardFormatAvailable")
	procRegisterClipboardFormatW      = user32.NewProc("RegisterClipboardFormatW")
	procGetClipboardSequenceNumber    = user32.NewProc("GetClipboardSequenceNumber")
	procGetClipboardOwner             = user32.NewProc("GetClipboardOwner")

	procGlobalAlloc  = kernel32.NewProc("GlobalAlloc")
	procGlobalFree   = kernel32.NewProc("GlobalFree")
	procGlobalLock   = kernel32.NewProc("GlobalLock")
	procGlobalUnlock = kernel32.NewProc("GlobalUnlock")
	procGlobalSize   = kernel32.NewProc("GlobalSize")
)

const (
	wmDestroy         = 0x0002
	wmClose           = 0x0010
	wmClipboardUpdate = 0x031D
	cfUnicodeText     = 13
	gmemMoveable      = 0x0002
	className         = "SentinelGoDLPClipboard"

	openRetries = 10
	openBackoff = 15 * time.Millisecond

	// maxReadChars bounds how much clipboard text is copied out (16 MB of
	// UTF-16). Scanning is bounded separately by max_scan_bytes.
	maxReadChars = 8 << 20
)

// hwndMessage is HWND_MESSAGE ((HWND)-3): a message-only window.
var hwndMessage = ^uintptr(2)

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       windows.Handle
	Cursor     windows.Handle
	Background windows.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     windows.Handle
}

type winMsg struct {
	Hwnd     uintptr
	Message  uint32
	WParam   uintptr
	LParam   uintptr
	Time     uint32
	Pt       [2]int32
	LPrivate uint32
}

// Formats password managers set on their copies (nspasteboard.org's Windows
// counterparts), and the ones we set on our placeholder.
var (
	fmtExcludeMonitor  = registerFormat("ExcludeClipboardContentFromMonitorProcessing")
	fmtViewerIgnore    = registerFormat("Clipboard Viewer Ignore")
	fmtIncludeHistory  = registerFormat("CanIncludeInClipboardHistory")
	fmtUploadToCloudCB = registerFormat("CanUploadToCloudClipboard")
)

func registerFormat(name string) func() uintptr {
	var once sync.Once
	var id uintptr
	return func() uintptr {
		once.Do(func() {
			p, _ := windows.UTF16PtrFromString(name)
			id, _, _ = procRegisterClipboardFormatW.Call(uintptr(unsafe.Pointer(p))) // #nosec G103 -- Win32 string argument
		})
		return id
	}
}

// The window class and its callback are created once per process: Go
// callbacks are a limited resource.
var (
	classOnce sync.Once
	errClass  error

	watchersMu sync.Mutex
	watchers   = map[uintptr]*watcher{}
)

func registerClass() error {
	classOnce.Do(func() {
		name, _ := windows.UTF16PtrFromString(className)
		wc := wndClassEx{WndProc: windows.NewCallback(wndProc), ClassName: name}
		wc.Size = uint32(unsafe.Sizeof(wc))
		if r, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 { // #nosec G103 -- Win32 struct argument
			errClass = fmt.Errorf("register window class: %w", err)
		}
	})
	return errClass
}

func wndProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	switch msg {
	case wmClipboardUpdate:
		watchersMu.Lock()
		w := watchers[hwnd]
		watchersMu.Unlock()
		if w != nil {
			w.onUpdate(hwnd)
		}
		return 0
	case wmClose:
		_, _, _ = procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		_, _, _ = procRemoveClipboardFormatListener.Call(hwnd)
		_, _, _ = procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wparam, lparam)
	return r
}

type winChannel struct{}

// New returns the clipboard channel for this platform.
func New() channel.Channel { return winChannel{} }

func (winChannel) Name() string { return Name }

// Supported is false in session 0 (services have no clipboard of a user).
func (winChannel) Supported() channel.Capability {
	var s uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &s); err == nil && s == 0 {
		return channel.Unsupported("session_0")
	}
	if err := user32.Load(); err != nil {
		return channel.Unsupported("no_user32")
	}
	return channel.Supported()
}

// Known gap: Windows clipboard history (Win+V) and cloud clipboard record an
// item when it is copied, before the watcher sees it, so a blocked secret can
// stay in history (our placeholder is marked to stay out of it). Where DLP
// matters, disable both by Group Policy: "Allow Clipboard History" and "Allow
// Clipboard synchronization across devices" = Disabled (HKLM\SOFTWARE\Policies\
// Microsoft\Windows\System: AllowClipboardHistory=0, AllowCrossDeviceClipboard=0).

// Run watches the clipboard until ctx ends. It is event driven: no CPU is
// used while nothing is copied.
func (c winChannel) Run(ctx context.Context, p *policy.Compiled, sink channel.EventSink) error {
	if !c.Supported().Supported {
		return channel.ErrUnsupported
	}
	if err := registerClass(); err != nil {
		return err
	}
	w := &watcher{p: p, sink: sink}
	ready := make(chan uintptr, 1)
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // the window and its messages belong to this thread
		defer runtime.UnlockOSThread()
		errc <- w.loop(ready)
	}()
	var hwnd uintptr
	select {
	case hwnd = <-ready:
	case err := <-errc:
		return err
	}
	select {
	case <-ctx.Done():
		_, _, _ = procPostMessageW.Call(hwnd, wmClose, 0, 0)
		<-errc
		return ctx.Err()
	case err := <-errc:
		return err
	}
}

// watcher is one running clipboard listener.
type watcher struct {
	p    *policy.Compiled
	sink channel.EventSink

	ownSeq    uintptr  // sequence number after our own write
	lastKey   [32]byte // last content + source app scanned...
	lastBlock bool     // ...and whether it was blocked
}

func (w *watcher) loop(ready chan<- uintptr) error {
	name, _ := windows.UTF16PtrFromString(className)
	hwnd, _, err := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(name)), 0, 0, 0, 0, 0, 0, hwndMessage, 0, 0, 0) // #nosec G103 -- Win32 string argument
	if hwnd == 0 {
		return fmt.Errorf("create clipboard window: %w", err)
	}
	watchersMu.Lock()
	watchers[hwnd] = w
	watchersMu.Unlock()
	defer func() {
		watchersMu.Lock()
		delete(watchers, hwnd)
		watchersMu.Unlock()
	}()
	if r, _, err := procAddClipboardFormatListener.Call(hwnd); r == 0 {
		_, _, _ = procDestroyWindow.Call(hwnd)
		return fmt.Errorf("listen for clipboard changes: %w", err)
	}
	ready <- hwnd

	var m winMsg
	for {
		r, _, err := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0) // #nosec G103 -- Win32 struct argument
		switch int32(r) {                                                       // #nosec G115 -- GetMessage returns BOOL (-1, 0 or nonzero)
		case 0:
			return nil // WM_QUIT
		case -1:
			return fmt.Errorf("clipboard message loop: %w", err)
		}
		_, _, _ = procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m))) // #nosec G103 -- Win32 struct argument
	}
}

// onUpdate handles one clipboard change on the window's thread.
func (w *watcher) onUpdate(hwnd uintptr) {
	seq, _, _ := procGetClipboardSequenceNumber.Call()
	if seq == w.ownSeq {
		return // our own placeholder
	}
	text, src, ok := w.read(hwnd)
	if !ok || text == "" {
		return
	}
	// Re-copying the same text from the same app: a monitor event was
	// already recorded. A blocked secret copied again is blocked again, and
	// the same text from another app (one a policy doesn't exempt) is new.
	key := dedupeKey(text, src)
	if key == w.lastKey && !w.lastBlock {
		return
	}
	d := Decide(w.p, text, src, time.Now())
	w.lastKey, w.lastBlock = key, d.Block
	if d.Block {
		if err := w.replace(hwnd, d.Message, seq); err != nil {
			// The content is still there: don't claim it was blocked.
			log.Printf("DLP helper: clipboard not replaced (%v); recording as monitored", err)
			markMonitored(d.Events)
		} else {
			w.ownSeq, _, _ = procGetClipboardSequenceNumber.Call()
		}
	}
	for _, ev := range d.Events {
		w.sink.Emit(ev)
	}
}

// read returns the clipboard's text and where it came from. ok is false when
// the clipboard couldn't be opened or the copy is marked concealed and the
// policy ignores those.
func (w *watcher) read(hwnd uintptr) (text string, src events.SourceApp, ok bool) {
	if !openClipboard(hwnd) {
		return "", src, false
	}
	defer func() { _, _, _ = procCloseClipboard.Call() }()

	if w.p.Modules.Clipboard.IgnoreConcealed && concealed() {
		return "", src, false
	}
	src = sourceApp()
	if r, _, _ := procIsClipboardFormatAvailable.Call(cfUnicodeText); r == 0 {
		return "", src, true
	}
	h, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if h == 0 {
		return "", src, true
	}
	return globalText(h), src, true
}

// concealed reports whether the copy came from a password manager or other
// app that asked monitors to ignore it. Any app can set these markers: with
// ignore_concealed the admin chooses to trust them, which fits the threat
// model (accidental leaks, not a user deliberately evading DLP).
func concealed() bool {
	for _, f := range []uintptr{fmtExcludeMonitor(), fmtViewerIgnore()} {
		if r, _, _ := procIsClipboardFormatAvailable.Call(f); f != 0 && r != 0 {
			return true
		}
	}
	// CanIncludeInClipboardHistory = 0 is how KeePass and others mark secrets.
	if f := fmtIncludeHistory(); f != 0 {
		if r, _, _ := procIsClipboardFormatAvailable.Call(f); r != 0 {
			if h, _, _ := procGetClipboardData.Call(f); h != 0 {
				if v, ok := globalDWORD(h); ok && v == 0 {
					return true
				}
			}
		}
	}
	return false
}

// replace puts msg on the clipboard in place of the content, marked so
// monitors, Win+V history and cloud clipboard skip it.
// errNewerCopy: another copy replaced the scanned one before we could act;
// that copy gets its own update.
var errNewerCopy = errors.New("a newer copy replaced the scanned content")

// replace swaps the content scanned at sequence number seq for msg, unless
// a newer copy has arrived meanwhile (that one is judged on its own).
func (w *watcher) replace(hwnd uintptr, msg string, seq uintptr) error {
	if !openClipboard(hwnd) {
		return errors.New("clipboard busy")
	}
	defer func() { _, _, _ = procCloseClipboard.Call() }()
	if now, _, _ := procGetClipboardSequenceNumber.Call(); now != seq {
		return errNewerCopy
	}
	if r, _, err := procEmptyClipboard.Call(); r == 0 {
		return err
	}
	u16, _ := windows.UTF16FromString(msg)
	if err := setGlobal(cfUnicodeText, u16Bytes(u16)); err != nil {
		return err
	}
	zero := []byte{0, 0, 0, 0}
	_ = setGlobal(fmtExcludeMonitor(), zero)
	_ = setGlobal(fmtIncludeHistory(), zero)
	_ = setGlobal(fmtUploadToCloudCB(), zero)
	return nil
}

func openClipboard(hwnd uintptr) bool {
	for range openRetries {
		if r, _, _ := procOpenClipboard.Call(hwnd); r != 0 {
			return true
		}
		time.Sleep(openBackoff) // another process holds it
	}
	return false
}

// setGlobal hands data to the clipboard as format f. The clipboard owns the
// memory once SetClipboardData succeeds.
func setGlobal(f uintptr, data []byte) error {
	if f == 0 {
		return errors.New("format not registered")
	}
	h, _, err := procGlobalAlloc.Call(gmemMoveable, uintptr(len(data)))
	if h == 0 {
		return err
	}
	if p := globalLock(h); p != nil {
		copy(unsafe.Slice((*byte)(p), len(data)), data) // #nosec G103 -- within the GlobalAlloc'd block
		_, _, _ = procGlobalUnlock.Call(h)
	}
	if r, _, err := procSetClipboardData.Call(f, h); r == 0 {
		_, _, _ = procGlobalFree.Call(h)
		return err
	}
	return nil
}

// globalLock returns the memory of a global handle, avoiding a uintptr to
// unsafe.Pointer conversion vet would flag.
func globalLock(h uintptr) unsafe.Pointer {
	r, _, _ := procGlobalLock.Call(h)
	return *(*unsafe.Pointer)(unsafe.Pointer(&r)) // #nosec G103 -- pointer returned by GlobalLock
}

// globalText reads a NUL-terminated UTF-16 string from a global handle,
// bounded by the block size.
func globalText(h uintptr) string {
	size, _, _ := procGlobalSize.Call(h)
	p := globalLock(h)
	if p == nil {
		return ""
	}
	defer func() { _, _, _ = procGlobalUnlock.Call(h) }()
	u16 := unsafe.Slice((*uint16)(p), min(size/2, maxReadChars)) // #nosec G103 -- bounded by GlobalSize
	for i, c := range u16 {
		if c == 0 {
			u16 = u16[:i]
			break
		}
	}
	return windows.UTF16ToString(u16)
}

func globalDWORD(h uintptr) (uint32, bool) {
	size, _, _ := procGlobalSize.Call(h)
	p := globalLock(h)
	if p == nil {
		return 0, false
	}
	defer func() { _, _, _ = procGlobalUnlock.Call(h) }()
	if size < 4 {
		return 0, false
	}
	return *(*uint32)(p), true
}

func u16Bytes(u []uint16) []byte {
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

// sourceApp identifies the app that put the content on the clipboard: the
// clipboard owner's process, else the foreground window's.
func sourceApp() events.SourceApp {
	owner, _, _ := procGetClipboardOwner.Call()
	hwnd := windows.HWND(owner)
	if hwnd == 0 {
		hwnd = windows.GetForegroundWindow()
	}
	if hwnd == 0 {
		return events.SourceApp{}
	}
	var pid uint32
	if _, err := windows.GetWindowThreadProcessId(hwnd, &pid); err != nil || pid == 0 {
		return events.SourceApp{}
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return events.SourceApp{}
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var buf [windows.MAX_LONG_PATH]uint16
	n := uint32(windows.MAX_LONG_PATH)
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return events.SourceApp{}
	}
	path := windows.UTF16ToString(buf[:n])
	name := path
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '\\' {
			name = path[i+1:]
			break
		}
	}
	return events.SourceApp{Name: name, Path: path}
}
