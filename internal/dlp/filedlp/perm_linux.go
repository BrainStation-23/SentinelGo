package filedlp

// Blocking on Linux (#333, fail-safes #329): a second fanotify group, of
// class content, holds the *creation* of files on monitored destinations
// (FAN_OPEN_PERM on their mounts) while the agent decides.
//
// What is judged: a new (empty) regular file opened on a destination by a
// copy program (cp, rsync, a file manager: copyPrograms), by the files it has
// open for reading at that moment, since those programs hold the source open
// while they create the copy. A source matching a block policy makes the
// open fail with EPERM: nothing is written. Every other open (reads,
// existing files, other programs, our own process) is allowed; files
// overwritten in place, and writes by other programs, are left to the
// after-write path (on_close_violation, process taint), which judges what
// was actually written.
//
// Fail-safes, all ending in "allow":
//   - permGate: one answer per open, a timer (scan_timeout_ms, at most
//     permMaxWait) answers on_timeout, overload answers at once;
//   - a watchdog closes the group when the read loop stops making progress,
//     which makes the kernel allow everything still held;
//   - the group runs only while a policy enforces block (not audit-only),
//     a destination is mounted, and the emergency switch is off;
//   - stopping the hook answers everything held, then closes the group.

import (
	"context"
	"encoding/binary"
	"log"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"sentinelgo/internal/dlp/policy"
)

// Permission hook tuning.
const (
	permMaxPending = 64               // opens held at once; more are allowed at once
	permMaxWait    = 10 * time.Second // the longest an open is held
	permMinWait    = 200 * time.Millisecond
	permReplyLen   = 8 // sizeof(struct fanotify_response)
)

// permStallAfter is the read loop's silence that trips the watchdog (a var
// for tests).
var permStallAfter = 5 * time.Second

// Test seams for the permission group.
var (
	permInit = func() (int, error) {
		return unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK,
			unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
	}
	permMark = func(fan int, add bool, mountPoint string) error {
		flags := uint(unix.FAN_MARK_MOUNT)
		if add {
			flags |= unix.FAN_MARK_ADD
		} else {
			flags |= unix.FAN_MARK_REMOVE
		}
		return unix.FanotifyMark(fan, flags, unix.FAN_OPEN_PERM, unix.AT_FDCWD, mountPoint)
	}
	permWrite = func(fan, fd int, allow bool) error {
		var buf [permReplyLen]byte
		resp := uint32(unix.FAN_DENY)
		if allow {
			resp = unix.FAN_ALLOW
		}
		binary.NativeEndian.PutUint32(buf[0:], uint32(int32(fd))) // #nosec G115 -- the kernel's event fd
		binary.NativeEndian.PutUint32(buf[4:], resp)
		_, err := unix.Write(fan, buf[:])
		return err
	}
	statPath fileStat = func(path string) (uint64, uint64, int64, bool) {
		var st unix.Stat_t
		if err := unix.Stat(path, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
			return 0, 0, 0, false
		}
		return st.Dev, st.Ino, st.Size, true // #nosec G115 -- device numbers
	}
)

// Blocking states, reported in Health.Blocking.
const (
	blockingOff      = "off" // no policy enforces block, or nothing is mounted
	blockingWatchdog = "stopped:watchdog"
)

// permHook is one permission group. Owned by the mount loop; stopped by it
// or by stopLocked after the loops ended.
type permHook struct {
	e         *linuxEnforcer
	fan       int
	gate      *permGate
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	beat      atomic.Int64 // the read loop's last iteration, Unix ns
	marked    map[string]bool
	closeOnce sync.Once
	tripped   atomic.Bool
}

// blockingWanted reports whether a policy may block a file on a Linux
// channel: the module enforces and some policy's action is block.
func blockingWanted(c *policy.Compiled) bool {
	if c == nil || c.Modules.Files.IsAuditOnly() {
		return false
	}
	for ch := range linuxChannels {
		if !c.ChannelEnabled(ch) {
			continue
		}
		for _, p := range c.For(ch) {
			if p.Action == policy.ActionBlock {
				return true
			}
		}
	}
	return false
}

// reconcilePerm starts, stops and re-marks the permission group to match
// the current destinations. Called from the mount loop only.
func (e *linuxEnforcer) reconcilePerm(c *policy.Compiled, off bool) {
	dests := *e.dests.Load()
	want := blockingWanted(c) && !off && len(dests) > 0 && e.permFailure.Load() == nil
	h := e.perm.Load()
	if h != nil && h.tripped.Load() {
		e.stopPerm() // the watchdog closed it; it stays off until the hook restarts
		r := blockingWatchdog
		e.permFailure.Store(&r)
		return
	}
	if !want {
		if h != nil {
			e.stopPerm()
		}
		return
	}
	if h == nil {
		if h = e.startPerm(); h == nil {
			return
		}
	}
	keep := map[string]bool{}
	for _, d := range dests {
		keep[d.Mount] = true
		if !h.marked[d.Mount] {
			if err := permMark(h.fan, true, d.Mount); err != nil {
				log.Printf("DLP: can't hold file creation on a %s mount: %v", d.Type, err)
				continue
			}
			h.marked[d.Mount] = true
		}
	}
	for mp := range h.marked {
		if !keep[mp] {
			_ = permMark(h.fan, false, mp)
			delete(h.marked, mp)
		}
	}
}

func (e *linuxEnforcer) startPerm() *permHook {
	fan, err := permInit()
	if err != nil {
		r := fanotifyFailure(err)
		e.permFailure.Store(&r)
		log.Printf("DLP: file blocking unavailable: fanotify permission events: %v", err)
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &permHook{e: e, fan: fan, cancel: cancel, marked: map[string]bool{}}
	h.gate = newPermGate(permMaxPending, func(id int, allow bool) {
		if err := permWrite(fan, id, allow); err != nil {
			log.Printf("DLP: file blocking: answering the kernel failed: %v", err)
		}
		_ = unix.Close(id)
	})
	h.beat.Store(time.Now().UnixNano())
	h.wg.Add(2)
	go h.readLoop(ctx)
	go h.watchdog(ctx)
	e.perm.Store(h)
	log.Printf("DLP: file blocking started (removable media and network shares)")
	return h
}

// stopPerm answers everything held with allow, then closes the group (the
// kernel allows anything still pending and drops the marks).
func (e *linuxEnforcer) stopPerm() {
	h := e.perm.Swap(nil)
	if h == nil {
		return
	}
	e.lastPerm.Store(ptrTo(h.gate.stats()))
	h.cancel()
	h.gate.stop()
	h.wg.Wait()
	h.close()
	log.Printf("DLP: file blocking stopped")
}

func (h *permHook) close() {
	h.closeOnce.Do(func() { _ = unix.Close(h.fan) })
}

// watchdog closes the group when the read loop stalls: everything held is
// then allowed by the kernel, and blocking stays off (reported) until the
// file hook restarts.
func (h *permHook) watchdog(ctx context.Context) {
	defer h.wg.Done()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if time.Since(time.Unix(0, h.beat.Load())) > permStallAfter {
			log.Printf("DLP: file blocking: the event loop stalled; allowing everything and turning blocking off")
			h.tripped.Store(true)
			h.gate.stop()
			h.close()
			return
		}
	}
}

func (h *permHook) readLoop(ctx context.Context) {
	defer h.wg.Done()
	buf := make([]byte, 64<<10)
	self := os.Getpid()
	for ctx.Err() == nil && !h.tripped.Load() {
		h.beat.Store(time.Now().UnixNano())
		fds := []unix.PollFd{{Fd: int32(h.fan), Events: unix.POLLIN}} // #nosec G115 -- a descriptor
		if n, err := unix.Poll(fds, readPollMs); err != nil || n == 0 {
			continue
		}
		n, err := unix.Read(h.fan, buf)
		if err != nil || n < metaLen {
			continue
		}
		for off := 0; off+metaLen <= n; {
			evLen := int(binary.NativeEndian.Uint32(buf[off:]))
			if evLen < metaLen || off+evLen > n {
				break
			}
			fd := int(int32(binary.NativeEndian.Uint32(buf[off+16:])))  // #nosec G115 -- the kernel's signed fd
			pid := int(int32(binary.NativeEndian.Uint32(buf[off+20:]))) // #nosec G115 -- the kernel's signed pid
			off += evLen
			if fd >= 0 {
				h.handle(fd, pid, self)
			}
		}
	}
}

// handle hands one held open to the gate. The read loop does nothing that
// can block (no file system access): fstat on a share, /proc reads and the
// scan all run in the gate's goroutine, under its timer. The timer always
// allows here: on_timeout applies to scans of the written file (after the
// write), never to an open the agent was merely slow to look at.
func (h *permHook) handle(fd, pid, self int) {
	e := h.e
	c := e.compiled.Load()
	if pid == self || e.localOff.Load() || c == nil {
		h.gate.allowNow(fd)
		return
	}
	wait := min(max(time.Duration(c.Modules.Files.ScanTimeoutMs)*time.Millisecond, permMinWait), permMaxWait)
	h.gate.submit(fd, wait, false, func(ctx context.Context) bool { return h.judge(ctx, c, fd, pid) })
}

// judge decides one held open: block only a file being created on a
// destination whose process holds a source matching a block policy.
func (h *permHook) judge(ctx context.Context, c *policy.Compiled, fd, pid int) bool {
	e := h.e
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size > 0 {
		return false // only files being created are judged here
	}
	path, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return false
	}
	dest, ok := e.destinationOf(path)
	if !ok {
		return false
	}
	proc := processInfo(pid)
	if !isCopyProgram(proc) {
		return false // judged after the write, by what it wrote
	}
	isDest := func(p string) bool { _, ok := e.destinationOf(p); return ok }
	sources := openFileSources(procRoot, pid, isDest, statPath, maxOpenSources)
	if len(sources) == 0 || ctx.Err() != nil {
		return false
	}
	r := Request{Path: path, Dest: dest, Proc: proc, At: time.Now(), Sources: sources,
		Ident: Identity{Dev: st.Dev, Ino: st.Ino}} // #nosec G115 -- device numbers
	return e.decider.DecideBySources(ctx, r, MethodOpenFile).Block
}

// blockingHealth reports the permission hook.
func (e *linuxEnforcer) blockingHealth() *BlockingHealth {
	if h := e.perm.Load(); h != nil {
		return &BlockingHealth{State: stateRunning, Marks: len(*e.dests.Load()), PermStats: h.gate.stats()}
	}
	b := &BlockingHealth{State: blockingOff}
	if r := e.permFailure.Load(); r != nil {
		b.State = *r
	}
	if s := e.lastPerm.Load(); s != nil {
		b.PermStats = *s
		b.Pending = 0
	}
	return b
}
