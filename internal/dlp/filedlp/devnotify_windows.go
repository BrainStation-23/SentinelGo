package filedlp

// Letting a drive go (#330). An open directory handle on a USB stick makes
// "Safely remove" fail with "this device is in use", so every watch handle
// is registered for device events (RegisterDeviceNotification on a
// message-only window). When the user asks to remove the drive
// (DBT_DEVICEQUERYREMOVE), the watch is closed before the window answers,
// and the drive is left alone for a while so the removal can finish.

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wmDeviceChange             = 0x0219
	wmClose                    = 0x0010
	dbtDeviceQueryRemove       = 0x8001
	dbtDeviceQueryRemoveFailed = 0x8002
	dbtDeviceRemovePending     = 0x8003
	dbtDeviceRemoveComplete    = 0x8004
	dbtDevtypHandle            = 6
	deviceNotifyWindowHandle   = 0
	hwndMessage                = ^uintptr(2) // HWND_MESSAGE, (HWND)-3
)

var (
	devUser32                        = windows.NewLazySystemDLL("user32.dll")
	procDevRegisterClassExW          = devUser32.NewProc("RegisterClassExW")
	procDevCreateWindowExW           = devUser32.NewProc("CreateWindowExW")
	procDevDefWindowProcW            = devUser32.NewProc("DefWindowProcW")
	procDevGetMessageW               = devUser32.NewProc("GetMessageW")
	procDevDispatchMessageW          = devUser32.NewProc("DispatchMessageW")
	procDevDestroyWindow             = devUser32.NewProc("DestroyWindow")
	procDevPostQuitMessage           = devUser32.NewProc("PostQuitMessage")
	procRegisterDeviceNotificationW  = devUser32.NewProc("RegisterDeviceNotificationW")
	procUnregisterDeviceNotification = devUser32.NewProc("UnregisterDeviceNotification")
)

// devBroadcastHandle is DEV_BROADCAST_HANDLE.
type devBroadcastHandle struct {
	Size       uint32
	DeviceType uint32
	Reserved   uint32
	Handle     windows.Handle
	HDevNotify uintptr
	EventGUID  windows.GUID
	NameOffset int32
	Data       [1]byte
}

type devWndClassEx struct {
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

type devMsg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

// devNotifier owns the message-only window. One per process: the window
// procedure is a single callback (Windows limits how many can be made).
type devNotifier struct {
	mu      sync.Mutex
	hwnd    uintptr
	regs    map[windows.Handle]uintptr    // watch handle → HDEVNOTIFY
	onQuery map[windows.Handle]func(bool) // true: removal asked; false: it was cancelled
	started bool
	err     error
}

var (
	devNotify     = &devNotifier{regs: map[windows.Handle]uintptr{}, onQuery: map[windows.Handle]func(bool){}}
	devClassOnce  sync.Once
	devClassError error
	devClassName  = windows.StringToUTF16Ptr("SentinelGoFileDLPDevNotify")
)

// start creates the window on its own locked thread (once).
func (n *devNotifier) start() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.started {
		return n.err
	}
	n.started = true
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // the window and its messages belong to this thread
		devClassOnce.Do(func() {
			wc := devWndClassEx{WndProc: windows.NewCallback(devWndProc), ClassName: devClassName}
			wc.Size = uint32(unsafe.Sizeof(wc))
			if r, _, err := procDevRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
				devClassError = fmt.Errorf("RegisterClassExW: %w", err)
			}
		})
		if devClassError != nil {
			ready <- devClassError
			return
		}
		hwnd, _, err := procDevCreateWindowExW.Call(0, uintptr(unsafe.Pointer(devClassName)), 0, 0, 0, 0, 0, 0, hwndMessage, 0, 0, 0)
		if hwnd == 0 {
			ready <- fmt.Errorf("CreateWindowExW: %w", err)
			return
		}
		n.hwnd = hwnd // read by register under n.mu, which start holds until ready
		ready <- nil
		var m devMsg
		for {
			r, _, _ := procDevGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
			if int32(r) <= 0 { // #nosec G115 -- BOOL, -1 on error
				return
			}
			_, _, _ = procDevDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
		}
	}()
	n.err = <-ready
	return n.err
}

// register asks for device events on h; query is called (on the window's
// thread) with true when the user asks to remove the device and must close
// h before returning, and with false when that removal was cancelled.
func (n *devNotifier) register(h windows.Handle, query func(bool)) error {
	if err := n.start(); err != nil {
		return err
	}
	f := devBroadcastHandle{DeviceType: dbtDevtypHandle, Handle: h}
	f.Size = uint32(unsafe.Sizeof(f))
	n.mu.Lock()
	defer n.mu.Unlock()
	r, _, err := procRegisterDeviceNotificationW.Call(n.hwnd, uintptr(unsafe.Pointer(&f)), deviceNotifyWindowHandle)
	if r == 0 {
		return fmt.Errorf("RegisterDeviceNotificationW: %w", err)
	}
	n.regs[h] = r
	n.onQuery[h] = query
	return nil
}

// unregister stops device events for h.
func (n *devNotifier) unregister(h windows.Handle) {
	n.mu.Lock()
	r, ok := n.regs[h]
	delete(n.regs, h)
	delete(n.onQuery, h)
	n.mu.Unlock()
	if ok {
		_, _, _ = procUnregisterDeviceNotification.Call(r)
	}
}

func devWndProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	if msg == wmDeviceChange && lparam != 0 {
		hdr := *(**devBroadcastHandle)(unsafe.Pointer(&lparam)) // #nosec G103 -- lParam is the OS's DEV_BROADCAST_HDR
		if hdr.DeviceType == dbtDevtypHandle {
			devNotify.mu.Lock()
			fn := devNotify.onQuery[hdr.Handle]
			devNotify.mu.Unlock()
			if fn != nil {
				switch wparam {
				case dbtDeviceQueryRemove:
					fn(true)
				case dbtDeviceQueryRemoveFailed:
					fn(false)
				case dbtDeviceRemovePending, dbtDeviceRemoveComplete:
					fn(true)
				}
			}
			return 1 // TRUE: never veto a removal
		}
	}
	if msg == wmClose {
		_, _, _ = procDevDestroyWindow.Call(hwnd)
		_, _, _ = procDevPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDevDefWindowProcW.Call(hwnd, msg, wparam, lparam)
	return r
}
