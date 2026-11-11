package watch

// Linux: two fanotify notification groups, never permission events (a scan
// must never hold up a write).
//
//   - Writes: FAN_CLOSE_WRITE on the mount of each root (FAN_MARK_MOUNT), as
//     file DLP does for removable media. The kernel hands over a descriptor;
//     its /proc/self/fd link is the file's path.
//   - Renames: FAN_MOVED_TO on each root's file system
//     (FAN_MARK_FILESYSTEM), in a FAN_REPORT_DFID_NAME group (Linux 5.9+),
//     which reports the target folder's handle and the new name. A file
//     moved into Downloads from elsewhere on the same disk is never
//     written there, so FAN_CLOSE_WRITE alone would miss it. Without kernel
//     support the watch runs on writes alone.
//
// A mark covers a whole mount or file system, not just the root, so the
// caller filters paths by root. Events from the agent itself are ignored.

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// Test seams.
var (
	fanInit = unix.FanotifyInit
	fanMark = unix.FanotifyMark
)

const (
	readPollMs   = 500
	readBufSize  = 64 << 10
	deletedMark  = " (deleted)"
	procSelfFD   = "/proc/self/fd/"
	writeMarkSet = unix.FAN_CLOSE_WRITE
	moveMarkSet  = unix.FAN_MOVED_TO
)

type linuxWatch struct {
	cancel context.CancelFunc
	wg     sync.WaitGroup
	fds    []int
	once   sync.Once
}

func start(roots []string, h Handler) (Watcher, error) {
	writes, err := fanInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK,
		unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("fanotify: %w", err)
	}
	fail := failures{total: len(roots)}
	for _, root := range roots {
		if err := fanMark(writes, unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, writeMarkSet, unix.AT_FDCWD, root); err != nil {
			fail.add(err)
		}
	}
	if fail.n == len(roots) {
		_ = unix.Close(writes)
		return nil, fail.err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &linuxWatch{cancel: cancel, fds: []int{writes}}
	self := int32(os.Getpid()) // #nosec G115 -- a pid fits an int32 (pid_t)
	w.wg.Add(1)
	go w.readLoop(ctx, writes, func(ev fanEvent) { onWrite(ev, self, h) })

	if moves, mounts := startMoves(roots); moves >= 0 {
		w.fds = append(w.fds, moves)
		w.wg.Add(1)
		go w.readLoop(ctx, moves, func(ev fanEvent) { onMove(ev, self, mounts, h) })
		for _, fd := range mounts {
			w.fds = append(w.fds, fd)
		}
	}
	return w, fail.err()
}

// startMoves opens the rename group and marks each root's file system. It
// returns -1 when the kernel can't report names (older than 5.9) or no file
// system could be marked. mounts maps each file system id to a descriptor
// on it, for open_by_handle_at.
func startMoves(roots []string) (int, map[[2]int32]int) {
	fan, err := fanInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK|unix.FAN_REPORT_DFID_NAME,
		unix.O_RDONLY|unix.O_CLOEXEC)
	if err != nil {
		log.Printf("YARA: on-write: files moved into watched folders aren't seen (fanotify name reporting: %v)", err)
		return -1, nil
	}
	mounts := map[[2]int32]int{}
	for _, root := range roots {
		fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			continue
		}
		var st unix.Statfs_t
		if err := unix.Fstatfs(fd, &st); err != nil {
			_ = unix.Close(fd)
			continue
		}
		id := [2]int32{st.Fsid.Val[0], st.Fsid.Val[1]}
		if _, ok := mounts[id]; ok {
			_ = unix.Close(fd)
			continue
		}
		if err := fanMark(fan, unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM, moveMarkSet, unix.AT_FDCWD, root); err != nil {
			_ = unix.Close(fd)
			continue
		}
		mounts[id] = fd
	}
	if len(mounts) == 0 {
		_ = unix.Close(fan)
		return -1, nil
	}
	return fan, mounts
}

func (w *linuxWatch) Close() {
	w.once.Do(func() {
		w.cancel()
		w.wg.Wait()
		for _, fd := range w.fds {
			_ = unix.Close(fd)
		}
	})
}

// readLoop reads one group until ctx ends; it never blocks on a callback
// for longer than the callback takes.
func (w *linuxWatch) readLoop(ctx context.Context, fan int, fn func(fanEvent)) {
	defer w.wg.Done()
	buf := make([]byte, readBufSize)
	for ctx.Err() == nil {
		fds := []unix.PollFd{{Fd: int32(fan), Events: unix.POLLIN}} // #nosec G115 -- a descriptor
		if n, err := unix.Poll(fds, readPollMs); err != nil || n == 0 {
			continue
		}
		n, err := unix.Read(fan, buf)
		if err != nil || n < fanMetaLen {
			continue
		}
		parseFanEvents(buf[:n], fn)
	}
}

// onWrite handles a close-write: the path comes from the descriptor, which
// is closed at once (the scan opens the file again, by path, checked).
func onWrite(ev fanEvent, self int32, h Handler) {
	if ev.overflow() {
		h.Lost()
	}
	if ev.fd < 0 {
		return
	}
	fd := int(ev.fd)
	path, err := os.Readlink(procSelfFD + strconv.Itoa(fd))
	_ = unix.Close(fd)
	if err != nil || ev.pid == self || strings.HasSuffix(path, deletedMark) {
		return
	}
	h.Changed(path)
}

// onMove handles a rename into a folder: the folder's handle is opened
// (O_PATH, no read access) to learn its path.
func onMove(ev fanEvent, self int32, mounts map[[2]int32]int, h Handler) {
	if ev.overflow() {
		h.Lost()
	}
	if ev.fd >= 0 {
		_ = unix.Close(int(ev.fd)) // never sent in a FID group; closed if it is
	}
	if !ev.hasName || ev.pid == self {
		return
	}
	mfd, ok := mounts[ev.fsid]
	if !ok {
		return
	}
	dfd, err := unix.OpenByHandleAt(mfd, unix.NewFileHandle(ev.handleType, ev.handle), unix.O_PATH|unix.O_CLOEXEC)
	if err != nil {
		return // the folder is gone already
	}
	dir, err := os.Readlink(procSelfFD + strconv.Itoa(dfd))
	_ = unix.Close(dfd)
	if err != nil || strings.HasSuffix(dir, deletedMark) {
		return
	}
	h.Changed(strings.TrimSuffix(dir, "/") + "/" + ev.name)
}
