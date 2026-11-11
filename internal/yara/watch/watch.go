// Package watch reports files written or renamed into folders, for on-write
// threat hunting (#418). It uses the notifications file DLP already relies
// on, with no driver and no cgo: fanotify notification events on Linux
// (FAN_CLOSE_WRITE, plus FAN_MOVED_TO where the kernel reports names),
// ReadDirectoryChangesW on Windows and FSEvents on macOS.
//
// Notifications only: nothing here waits on a scan, blocks a write or reads
// a file. Callers get paths and decide (debounce, filter, scan) themselves.
package watch

import (
	"errors"
	"fmt"
)

// errNoRoots is returned by Start without roots.
var errNoRoots = errors.New("watch: no folder to watch")

// failures sums up the roots that couldn't be watched without naming them
// (logs never carry paths): how many, and the first error.
type failures struct {
	n, total int
	first    error
}

func (f *failures) add(err error) {
	f.n++
	if f.first == nil {
		f.first = err
	}
}

func (f *failures) err() error {
	switch {
	case f.total == 0:
		return errNoRoots
	case f.n == 0:
		return nil
	}
	return fmt.Errorf("%d of %d folders not watched: %w", f.n, f.total, f.first)
}

// ErrUnsupported is returned on an OS without a watcher.
var ErrUnsupported = errors.New("watch: on-write notifications aren't supported on this OS")

// Handler receives notifications. Each callback must return quickly: it
// runs on the watcher's own goroutine (or the OS's dispatch queue), and the
// callbacks of one Watcher may run concurrently.
type Handler struct {
	// Changed gets the path of a file written, created or renamed into
	// place. It can be any file on a watched volume: callers filter by root.
	Changed func(path string)
	// Lost is called when notifications were dropped (a queue or buffer
	// overflowed).
	Lost func()
	// Gone is called when a watched root went away (unmounted, deleted);
	// that root isn't watched any more.
	Gone func(root string)
}

// Watcher is a running watch.
type Watcher interface {
	// Close stops the watch; no callback runs after it returns.
	Close()
}

// Start watches roots recursively. It returns a Watcher when at least one
// root is watched, and an error naming the roots that couldn't be (both
// may be set).
func Start(roots []string, h Handler) (Watcher, error) {
	if h.Changed == nil {
		h.Changed = func(string) {}
	}
	if h.Lost == nil {
		h.Lost = func() {}
	}
	if h.Gone == nil {
		h.Gone = func(string) {}
	}
	return start(roots, h)
}
