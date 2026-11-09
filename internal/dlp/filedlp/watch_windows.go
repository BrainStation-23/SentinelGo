package filedlp

// Watching a drive for written files (#330): one ReadDirectoryChangesW per
// volume root, recursive, overlapped so it can be cancelled. It works on
// NTFS, FAT32 and exFAT alike. Windows only says a name changed, never that
// a writer is done, so the enforcer waits until a file has been quiet and
// can be opened without write sharing (watchPending) before it scans it.

import (
	"errors"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// watchMask is what a watch reports: names (created, renamed into place)
// and contents (size, last write).
const watchMask = windows.FILE_NOTIFY_CHANGE_FILE_NAME | windows.FILE_NOTIFY_CHANGE_SIZE | windows.FILE_NOTIFY_CHANGE_LAST_WRITE

// watchBufSize is the notification buffer; 64 KiB is also the most a
// network redirector accepts.
const watchBufSize = 64 << 10

// dirWatch is a running watch on one root.
type dirWatch struct {
	root   string
	dir    windows.Handle
	stop   windows.Handle // event: set to end the loop
	done   chan struct{}
	closed sync.Once
}

// startWatch opens root and reports each changed file to change and each
// lost batch (buffer overflow) to overflow, until close or until the volume
// goes away (then gone is called once).
func startWatch(root string, change func(fsChange), overflow func(root string), gone func(root string)) (*dirWatch, error) {
	p, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return nil, err
	}
	dir, err := windows.CreateFile(p, windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return nil, err
	}
	stop, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(dir)
		return nil, err
	}
	w := &dirWatch{root: root, dir: dir, stop: stop, done: make(chan struct{})}
	go w.loop(change, overflow, gone)
	return w, nil
}

// close ends the watch and closes its handle (so the drive can be ejected).
// It waits for the loop. Safe to call more than once and from any goroutine.
func (w *dirWatch) close() {
	w.closed.Do(func() {
		_ = windows.SetEvent(w.stop)
		<-w.done
		_ = windows.CloseHandle(w.dir)
		_ = windows.CloseHandle(w.stop)
	})
}

func (w *dirWatch) loop(change func(fsChange), overflow func(root string), gone func(root string)) {
	defer close(w.done)
	ioEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		gone(w.root)
		return
	}
	defer func() { _ = windows.CloseHandle(ioEvent) }()
	buf := make([]byte, watchBufSize)
	for {
		n, st := w.next(ioEvent, buf)
		switch st {
		case watchStopped:
			return
		case watchGone:
			gone(w.root) // the volume was removed or dismounted
			return
		case watchOverflow:
			overflow(w.root) // too much changed at once: the buffer overflowed
		case watchChanges:
			for _, name := range parseNotify(buf[:n]) {
				change(fsChange{root: w.root, path: filepath.Join(w.root, name)})
			}
		}
	}
}

type watchStatus int

const (
	watchChanges watchStatus = iota
	watchOverflow
	watchGone
	watchStopped
)

// next waits for one batch of notifications into buf, or for close.
func (w *dirWatch) next(ioEvent windows.Handle, buf []byte) (uint32, watchStatus) {
	ov := windows.Overlapped{HEvent: ioEvent}
	_ = windows.ResetEvent(ioEvent)
	err := windows.ReadDirectoryChanges(w.dir, &buf[0], uint32(len(buf)), true, watchMask, nil, &ov, 0)
	if err != nil && !errors.Is(err, windows.ERROR_IO_PENDING) {
		return 0, watchGone
	}
	var n uint32
	ev, _ := windows.WaitForMultipleObjects([]windows.Handle{ioEvent, w.stop}, false, windows.INFINITE)
	if ev == windows.WAIT_OBJECT_0+1 {
		_ = windows.CancelIoEx(w.dir, &ov)
		_ = windows.GetOverlappedResult(w.dir, &ov, &n, true) // wait: buf must outlive the I/O
		return 0, watchStopped
	}
	err = windows.GetOverlappedResult(w.dir, &ov, &n, false)
	switch {
	case errors.Is(err, windows.ERROR_NOTIFY_ENUM_DIR), err == nil && n == 0:
		return 0, watchOverflow
	case err != nil:
		return 0, watchGone
	}
	return n, watchChanges
}

// parseNotify reads the FILE_NOTIFY_INFORMATION records in b and returns the
// names (relative to the root) of files added, modified or renamed into
// place. Removals and old names are of no interest.
func parseNotify(b []byte) []string {
	const hdr = 12 // NextEntryOffset, Action, FileNameLength
	var out []string
	for off := 0; off+hdr <= len(b); {
		next := int(le32(b[off:]))
		action := le32(b[off+4:])
		nameLen := int(le32(b[off+8:]))
		if off+hdr+nameLen > len(b) || nameLen%2 != 0 {
			break
		}
		switch action {
		case windows.FILE_ACTION_ADDED, windows.FILE_ACTION_MODIFIED, windows.FILE_ACTION_RENAMED_NEW_NAME:
			u := make([]uint16, nameLen/2)
			for i := range u {
				u[i] = uint16(b[off+hdr+2*i]) | uint16(b[off+hdr+2*i+1])<<8
			}
			out = append(out, windows.UTF16ToString(u))
		}
		if next <= 0 {
			break
		}
		off += next
	}
	return out
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// Ensure FILE_NOTIFY_INFORMATION's header is what parseNotify assumes.
var _ = [1]struct{}{}[unsafe.Offsetof(windows.FileNotifyInformation{}.FileName)-12]
