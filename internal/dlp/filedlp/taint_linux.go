package filedlp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"sentinelgo/internal/dlp/policy"
)

// Process taint on Linux: a second fanotify group gets notification events
// (FAN_OPEN) for opens on the mount holding the home folders, only while
// taint is on and a destination is watched. It has its own reader, so a flood
// of opens (a build, npm install) can only overflow its own queue, never push
// out the destination events. Each open costs a readlink and an fstat; the
// path and identity go into the in-memory taint store. Nothing is scanned.

// Test seams: where users' files live, and the open marks.
var (
	taintRoot = "/home"
	markOpens = func(fan int, add bool, mountPoint string) error {
		flags := uint(unix.FAN_MARK_MOUNT)
		if add {
			flags |= unix.FAN_MARK_ADD
		} else {
			flags |= unix.FAN_MARK_REMOVE
		}
		return unix.FanotifyMark(fan, flags, unix.FAN_OPEN, unix.AT_FDCWD, mountPoint)
	}
)

// taintHook is the open-watching group.
type taintHook struct {
	fan       int
	store     *taintStore
	marked    bool
	overflows uint64
	mu        sync.Mutex // guards overflows for Health
}

// startTaint opens the open-watching group and its reader, the first time
// taint is needed. It runs in the mount loop, which holds a wg count, so the
// Add below is safe against stopLocked's Wait.
func (e *linuxEnforcer) startTaint(ctx context.Context) *taintHook {
	fan, err := fanotifyInit()
	if err != nil {
		return nil // tried again on the next pass
	}
	t := &taintHook{fan: fan, store: newTaintStore()}
	e.taint.Store(t)
	e.wg.Add(1)
	go e.readTaintLoop(ctx, t)
	return t
}

// stopTaint closes the group (removing its mark). The loops have ended.
func (e *linuxEnforcer) stopTaint() {
	if t := e.taint.Swap(nil); t != nil {
		_ = unix.Close(t.fan)
	}
}

// reconcileTaint marks the home folders' mount while taint is on and a
// destination is watched, and unmarks it otherwise. The group is only
// opened once taint is first needed.
func (e *linuxEnforcer) reconcileTaint(ctx context.Context, c *policy.Compiled, watching bool) {
	want := watching && c != nil && c.Modules.Files.CopyCorrelation.ProcessTaint
	t := e.taint.Load()
	if t == nil && want {
		t = e.startTaint(ctx)
	}
	if t == nil {
		return
	}
	switch {
	case want && !t.marked:
		t.marked = markOpens(t.fan, true, taintRoot) == nil
	case !want && t.marked:
		_ = markOpens(t.fan, false, taintRoot)
		t.marked = false
	}
	if c != nil {
		t.store.prune(time.Now(), time.Duration(c.Modules.Files.CopyCorrelation.TaintWindowSeconds)*time.Second)
	}
}

// readTaintLoop records opens of files under taintRoot.
func (e *linuxEnforcer) readTaintLoop(ctx context.Context, t *taintHook) {
	defer e.wg.Done()
	buf := make([]byte, 64<<10)
	self := os.Getpid()
	prefix := strings.TrimSuffix(taintRoot, "/") + "/"
	for ctx.Err() == nil {
		fds := []unix.PollFd{{Fd: int32(t.fan), Events: unix.POLLIN}} // #nosec G115 -- a descriptor
		if n, err := unix.Poll(fds, readPollMs); err != nil || n == 0 {
			continue
		}
		n, err := unix.Read(t.fan, buf)
		if err != nil || n < metaLen {
			continue
		}
		for off := 0; off+metaLen <= n; {
			evLen := int(binary.NativeEndian.Uint32(buf[off:]))
			if evLen < metaLen || off+evLen > n {
				break
			}
			mask := binary.NativeEndian.Uint64(buf[off+8:])
			fd := int(int32(binary.NativeEndian.Uint32(buf[off+16:])))  // #nosec G115 -- the kernel's signed fd
			pid := int(int32(binary.NativeEndian.Uint32(buf[off+20:]))) // #nosec G115 -- the kernel's signed pid
			off += evLen
			if mask&unix.FAN_Q_OVERFLOW != 0 {
				t.mu.Lock()
				t.overflows++
				t.mu.Unlock()
			}
			if fd < 0 {
				continue
			}
			if pid != self {
				recordOpen(t.store, fd, pid, prefix)
			}
			_ = unix.Close(fd)
		}
	}
}

// recordOpen notes a regular file under prefix opened by pid.
func recordOpen(store *taintStore, fd, pid int, prefix string) {
	path, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil || !strings.HasPrefix(path, prefix) {
		return
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return
	}
	store.record(pid, SourceRef{Path: path, Dev: st.Dev, Ino: st.Ino, At: time.Now()}) // #nosec G115 -- device numbers
}

// taintSources returns what pid read before writing r, when taint is on.
func (e *linuxEnforcer) taintSources(c *policy.Compiled, pid int) []SourceRef {
	t := e.taint.Load()
	if t == nil || c == nil || !c.Modules.Files.CopyCorrelation.ProcessTaint {
		return nil
	}
	window := time.Duration(c.Modules.Files.CopyCorrelation.TaintWindowSeconds) * time.Second
	return t.store.sources(pid, procStartTime(pid), time.Now(), window)
}

// openSource reopens a file a process read, read-only and without following
// a symlink, and checks it is still the same file (device and inode).
func openSource(src SourceRef) (*os.File, Identity, error) {
	fd, err := unix.Open(src.Path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, Identity{}, errFileChanged
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Dev != src.Dev || st.Ino != src.Ino { // #nosec G115 -- device numbers
		_ = unix.Close(fd)
		return nil, Identity{}, errFileChanged
	}
	f := os.NewFile(uintptr(fd), filepath.Base(src.Path))                                                                 // #nosec G115 -- a descriptor
	return f, Identity{Dev: st.Dev, Ino: st.Ino, Size: st.Size, ModTime: st.Mtim.Nano(), ChangeTime: st.Ctim.Nano()}, nil // #nosec G115 -- device numbers
}

// procStartTime is when pid started (zero if unknown), from
// /proc/<pid>/stat's starttime and the boot time in /proc/stat.
func procStartTime(pid int) time.Time {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat")) // #nosec G304 -- procfs
	if err != nil {
		return time.Time{}
	}
	// The command name can hold spaces and parentheses: fields start after
	// the last ")"; starttime is field 22, the 20th after it.
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return time.Time{}
	}
	fields := strings.Fields(string(b[i+1:]))
	if len(fields) < 20 {
		return time.Time{}
	}
	ticks, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil {
		return time.Time{}
	}
	boot, err := bootTime()
	if err != nil {
		return time.Time{}
	}
	const clkTck = 100 // USER_HZ on every Linux architecture Go supports
	return boot.Add(time.Duration(ticks) * time.Second / clkTck)
}

func bootTime() (time.Time, error) {
	b, err := os.ReadFile(filepath.Join(procRoot, "stat")) // #nosec G304 -- procfs
	if err != nil {
		return time.Time{}, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "btime "); ok {
			s, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
			if err != nil {
				return time.Time{}, err
			}
			return time.Unix(s, 0), nil
		}
	}
	return time.Time{}, errors.New("no btime in /proc/stat")
}
