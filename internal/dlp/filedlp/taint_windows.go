package filedlp

// Process attribution and taint on Windows (#331), from the ETW opens
// (etw_windows.go). Only while process_taint is on and a drive is watched:
//
//   - an open under the user profiles folder by process P is a source in
//     P's taint (as on Linux: opens, not reads; nothing is scanned);
//   - an open on a watched drive tells which program wrote the file there,
//     so its event names the program and its user, and a file that can't be
//     judged on its own (unreadable, an archive) is judged by what that
//     program opened before.
//
// ETW gives NT paths (\Device\HarddiskVolume3\…); they are mapped to drive
// letters with QueryDosDevice.

import (
	"errors"
	"hash/fnv"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"

	"sentinelgo/internal/dlp/policy"
)

// maxWriters bounds the remembered writers of files on watched drives.
const maxWriters = 8192

type winTaint struct {
	sess  *etwSession
	store *taintStore

	devices  atomic.Pointer[[]ntPrefix] // NT device → drive letter
	profiles string                     // C:\Users\ (lower case)
	watched  atomic.Pointer[[]string]   // watched roots (lower case)

	mu      sync.Mutex
	writers map[string]writerRef // lower-case path on a watched drive → last opener
}

type ntPrefix struct{ nt, dos string }

type writerRef struct {
	pid uint32
	at  time.Time
}

// Test seam: what starts the trace.
var startTrace = startETW

// reconcileTaint starts the trace when taint is on and a drive is watched,
// and stops it otherwise.
func (e *windowsEnforcer) reconcileTaint(c *policy.Compiled, watched []Destination) {
	want := c != nil && len(watched) > 0 && c.Modules.Files.CopyCorrelation.ProcessTaint
	t := e.taint.Load()
	switch {
	case want && t == nil:
		if e.taintFailed.Load() {
			return // not until the next start
		}
		t = &winTaint{store: newTaintStore(), writers: map[string]writerRef{}, profiles: profilesDir()}
		t.refresh(watched)
		sess, err := startTrace(t.onOpen)
		if err != nil {
			e.taintFailed.Store(true)
			reason := etwFailure(err)
			e.taintError.Store(&reason)
			return
		}
		t.sess = sess
		e.taint.Store(t)
	case !want && t != nil:
		e.stopTaint()
	case want:
		t.refresh(watched)
		t.store.prune(time.Now(), time.Duration(c.Modules.Files.CopyCorrelation.TaintWindowSeconds)*time.Second)
		t.pruneWriters(time.Now(), time.Duration(c.Modules.Files.CopyCorrelation.TaintWindowSeconds)*time.Second)
	}
}

func etwFailure(err error) string {
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return "not_permitted"
	}
	if !etwAvailable {
		return "etw_unavailable"
	}
	return "etw_error"
}

func (e *windowsEnforcer) stopTaint() {
	if t := e.taint.Swap(nil); t != nil && t.sess != nil {
		t.sess.stop()
	}
}

// refresh updates the device map and the watched roots.
func (t *winTaint) refresh(watched []Destination) {
	devs := ntDevices()
	t.devices.Store(&devs)
	roots := make([]string, 0, len(watched))
	for _, d := range watched {
		roots = append(roots, strings.ToLower(strings.TrimSuffix(d.Mount, `\`)+`\`))
	}
	t.watched.Store(&roots)
}

// onOpen runs on the trace's thread for every open: keep it cheap.
func (t *winTaint) onOpen(o fileOpen) {
	path, ok := t.dosPath(o.path)
	if !ok {
		return
	}
	lower := strings.ToLower(path)
	now := time.Now()
	for _, root := range *t.watched.Load() {
		if strings.HasPrefix(lower, root) {
			t.mu.Lock()
			if len(t.writers) >= maxWriters {
				clear(t.writers)
			}
			t.writers[lower] = writerRef{pid: o.pid, at: now}
			t.mu.Unlock()
			return
		}
	}
	if t.profiles != "" && strings.HasPrefix(lower, t.profiles) {
		t.store.record(int(o.pid), SourceRef{Path: path, Ino: pathKey(lower), At: now})
	}
}

// dosPath maps an NT path to a drive-letter path.
func (t *winTaint) dosPath(nt string) (string, bool) {
	for _, p := range *t.devices.Load() {
		if len(nt) > len(p.nt) && nt[len(p.nt)] == '\\' && strings.EqualFold(nt[:len(p.nt)], p.nt) {
			return p.dos + nt[len(p.nt):], true
		}
	}
	return "", false
}

// writer is the program that last opened path on a watched drive, within
// window.
func (t *winTaint) writer(path string, now time.Time, window time.Duration) (uint32, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	w, ok := t.writers[strings.ToLower(path)]
	if !ok || now.Sub(w.at) > window {
		return 0, false
	}
	return w.pid, true
}

func (t *winTaint) pruneWriters(now time.Time, window time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, w := range t.writers {
		if now.Sub(w.at) > window {
			delete(t.writers, k)
		}
	}
}

// pathKey stands in for an inode in the taint store (ETW gives a path, not
// an identity; the source is checked when it is reopened).
func pathKey(lower string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(lower))
	return h.Sum64()
}

// attribute fills r's writer and, with taint on, its sources.
func (e *windowsEnforcer) attribute(r *Request, c *policy.Compiled) {
	t := e.taint.Load()
	if t == nil || c == nil {
		return
	}
	window := time.Duration(c.Modules.Files.CopyCorrelation.TaintWindowSeconds) * time.Second
	pid, ok := t.writer(r.Path, r.At, window)
	if !ok {
		return
	}
	p, start := winProcessInfo(pid)
	if p.UID == "" {
		p.UID, p.User = r.Proc.UID, r.Proc.User // exited: keep the console user
	}
	r.Proc = p
	r.Sources = t.store.sources(int(pid), start, r.At, window)
}

// winProcessInfo describes pid: name, path, session and user, and when it
// started (zero if unknown).
func winProcessInfo(pid uint32) (Process, time.Time) {
	p := Process{PID: int(pid)}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return p, time.Time{}
	}
	defer func() { _ = windows.CloseHandle(h) }()
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &size) == nil {
		p.Exe = windows.UTF16ToString(buf[:size])
		p.Name = p.Exe[strings.LastIndexByte(p.Exe, '\\')+1:]
	}
	var session uint32
	if windows.ProcessIdToSessionId(pid, &session) == nil {
		p.UID = strconv.FormatUint(uint64(session), 10)
		p.User = sessionUserName(session)
	}
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &created, &exited, &kernel, &user) != nil {
		return p, time.Time{}
	}
	return p, time.Unix(0, created.Nanoseconds())
}

// ntDevices maps each drive letter's NT device (\Device\HarddiskVolume3) to
// the letter (C:).
func ntDevices() []ntPrefix {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	var out []ntPrefix
	buf := make([]uint16, 1024)
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		letter := string(rune('A'+i)) + ":"
		lp, _ := windows.UTF16PtrFromString(letter)
		n, err := windows.QueryDosDevice(lp, &buf[0], uint32(len(buf)))
		if err != nil || n == 0 {
			continue
		}
		out = append(out, ntPrefix{nt: windows.UTF16ToString(buf), dos: letter})
	}
	return out
}

// profilesDir is the user profiles folder (C:\Users\), lower case.
func profilesDir() string {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_UserProfiles, 0)
	if err != nil || dir == "" {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(dir, `\`) + `\`)
}

// openSourceWin reopens a file a process opened, read-only and sharing
// everything (it may still be open in that program), not following links.
func openSourceWin(src SourceRef) (*os.File, Identity, error) {
	p, err := windows.UTF16PtrFromString(src.Path)
	if err != nil {
		return nil, Identity{}, errFileChanged
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|fileFlagNoRecall, 0)
	if err != nil {
		return nil, Identity{}, errFileChanged
	}
	var fi windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &fi) != nil ||
		fi.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_OFFLINE|attrRecallOnOpen|attrRecallOnData) != 0 {
		_ = windows.CloseHandle(h)
		return nil, Identity{}, errFileChanged
	}
	id, err := handleIdentity(h)
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, Identity{}, errFileChanged
	}
	return os.NewFile(uintptr(h), src.Path), id, nil
}
