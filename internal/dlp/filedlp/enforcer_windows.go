package filedlp

// Windows file DLP without a driver (#330). User mode has no API that holds
// a file open or create while the agent decides, so Windows can't refuse a
// copy by its content before it lands. What it does instead:
//
//   - watches every removable drive (ReadDirectoryChangesW) and scans each
//     file once its writer is done, in the sandboxed scan workers; a file
//     that violates a policy is recorded, quarantined or deleted
//     (copy_correlation.on_close_violation), and the user is told why;
//   - makes untrusted removable devices read-only
//     (copy_correlation.untrusted_devices): prevention by device, not
//     content.
//
// Nothing here waits on the agent: a slow, stuck or crashed agent can't hang
// a copy. At worst a file isn't scanned (counted as dropped).

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"sentinelgo/internal/dlp/filescan"
	"sentinelgo/internal/dlp/policy"
	"sentinelgo/internal/dlp/scanworker"
)

// windowsChannels are the file channels this hook monitors.
var windowsChannels = map[string]bool{policy.ChannelFileRemovable: true}

// workerEnv is extra environment for the scan workers (tests).
var workerEnv []string

// Tuning; vars for tests.
var (
	volumePoll    = 2 * time.Second
	quietFor      = time.Second     // a file must be unchanged this long before it is scanned
	tempQuietFor  = 5 * time.Second // longer for temp names: a save usually renames them first
	pendingTick   = 250 * time.Millisecond
	pendingGiveUp = 10 * time.Minute // a file still open for writing after this is dropped
	removeGrace   = 15 * time.Second // a drive being removed is left alone this long
	rescanWindow  = 5 * time.Minute  // after an overflow, files changed this recently are scanned
)

const (
	winQueueSize      = 256
	winDecideWorkers  = 2
	maxPending        = 4096
	changeQueueSize   = 4096
	maxRescanFiles    = 5000
	fileFlagNoRecall  = 0x00100000 // FILE_FLAG_OPEN_NO_RECALL
	attrRecallOnOpen  = 0x00040000 // FILE_ATTRIBUTE_RECALL_ON_OPEN
	attrRecallOnData  = 0x00400000 // FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
	winMethodsNoOSCpy = "not_on_windows"
)

type windowsEnforcer struct {
	opts    Options
	decider *Decider

	mu       sync.Mutex
	running  bool
	tried    bool
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	queue    chan Request
	changes  chan fsChange
	kick     chan struct{}
	devices  *winDeviceState // the volume loop's, then stopLocked's
	lastPool scanworker.Health

	pool     atomic.Pointer[scanworker.Pool]
	compiled atomic.Pointer[policy.Compiled]
	dests    atomic.Pointer[[]Destination] // watched volumes
	localOff atomic.Bool

	dropped, overflows, unreadable atomic.Uint64

	// Process attribution and taint (#331): nil while off.
	taint       atomic.Pointer[winTaint]
	taintFailed atomic.Bool            // the trace couldn't start; not tried again until restart
	taintError  atomic.Pointer[string] // why

	// Watches: the volume loop adds and removes them; the device window
	// closes one when its drive is being removed.
	wmu      sync.Mutex
	watches  map[string]*watchEntry // root → watch
	removing map[string]time.Time   // root → left alone until
}

type watchEntry struct {
	w    *dirWatch
	dest Destination
	dead atomic.Bool // the volume went away under it
}

// New returns the Windows file DLP enforcer.
func New(o Options) Enforcer {
	e := &windowsEnforcer{opts: o, devices: newWinDeviceState(), watches: map[string]*watchEntry{}, removing: map[string]time.Time{}}
	e.decider = NewDecider(winPoolScanner{e}, o.Sink)
	e.decider.SetSourceOpener(openSourceWin)
	if o.Notifier != nil {
		e.decider.SetUserNotifier(o.Notifier)
	}
	if o.RequestException != nil {
		e.decider.SetExceptionRequester(o.RequestException)
	}
	if o.ConfigDir != "" {
		e.decider.SetRemediator((&remediator{dir: filepath.Join(o.ConfigDir, QuarantineDir), now: time.Now}).remediate)
	}
	empty := []Destination{}
	e.dests.Store(&empty)
	return e
}

type winPoolScanner struct{ e *windowsEnforcer }

func (p winPoolScanner) Scan(ctx context.Context, f *os.File, size int64, timeout time.Duration) filescan.Result {
	pool := p.e.pool.Load()
	if pool == nil {
		return filescan.Result{Status: filescan.Unscannable(scanworker.ReasonWorkerFailed), Size: size}
	}
	return pool.Scan(ctx, f, size, timeout)
}

func (e *windowsEnforcer) Wants(m policy.FilesModule) bool { return wants(m, windowsChannels) }

func (e *windowsEnforcer) Apply(_ context.Context, c *policy.Compiled) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.compiled.Store(c)
	e.decider.Apply(c)
	if c == nil || !wants(c.Modules.Files, windowsChannels) {
		e.stopLocked()
		return
	}
	if !e.running {
		e.startLocked()
	}
	if pool := e.pool.Load(); pool != nil {
		if raw, err := json.Marshal(c.Bundle); err == nil {
			pool.SetPolicy(raw)
		}
	}
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

func (e *windowsEnforcer) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopLocked()
	e.compiled.Store(nil)
	e.decider.Apply(nil)
}

func (e *windowsEnforcer) startLocked() {
	e.tried = true
	e.taintFailed.Store(false) // a restart gives the trace another chance
	e.taintError.Store(nil)
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel, e.running = cancel, true
	e.queue = make(chan Request, winQueueSize)
	e.changes = make(chan fsChange, changeQueueSize)
	e.kick = make(chan struct{}, 1)
	pool := scanworker.NewPool(scanworker.Options{Exe: e.opts.Exe, Env: workerEnv})
	if c := e.compiled.Load(); c != nil {
		if raw, err := json.Marshal(c.Bundle); err == nil {
			pool.SetPolicy(raw)
		}
	}
	e.pool.Store(pool)
	e.wg.Add(2 + winDecideWorkers)
	go e.volumeLoop(ctx, e.kick)
	go e.pendingLoop(ctx, e.changes, e.queue)
	for i := 0; i < winDecideWorkers; i++ {
		go e.decideLoop(ctx, e.queue)
	}
	log.Printf("DLP: file monitoring started (removable drives: scanned after the write)")
}

func (e *windowsEnforcer) stopLocked() {
	if !e.running {
		return
	}
	e.running = false
	e.cancel()
	e.wg.Wait()
	e.stopTaint()
	e.wmu.Lock()
	roots := make([]string, 0, len(e.watches))
	for root := range e.watches {
		roots = append(roots, root)
	}
	e.wmu.Unlock()
	for _, root := range roots {
		e.releaseWatch(root)
	}
	for drained := false; !drained; {
		select {
		case r := <-e.queue:
			_ = r.File.Close()
		default:
			drained = true
		}
	}
	e.restoreDevices(e.devices) // fail open: nothing stays read-only because of us
	pool := e.pool.Swap(nil)
	e.lastPool = pool.Health()
	e.lastPool.Workers = 0
	pool.Stop()
	empty := []Destination{}
	e.dests.Store(&empty)
	log.Printf("DLP: file monitoring stopped")
}

// volumeLoop keeps a watch on every monitored removable drive, and
// untrusted devices read-only when asked: on start, every volumePoll, and
// when kicked.
func (e *windowsEnforcer) volumeLoop(ctx context.Context, kick <-chan struct{}) {
	defer e.wg.Done()
	t := time.NewTicker(volumePoll)
	defer t.Stop()
	for {
		off := e.offSwitch()
		e.localOff.Store(off)
		c := e.compiled.Load()
		vols := listVolumes()
		e.reconcileDevices(c, vols, off, e.devices)
		e.reconcileWatches(c, vols, off)
		e.reconcileTaint(c, *e.dests.Load())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-kick:
		}
	}
}

// monitoredVolumes are the volumes to watch under c: removable drives whose
// channel is on, not trusted, writable, and not being removed; none when
// scanning after the write is off or the emergency switch is on.
func (e *windowsEnforcer) monitoredVolumes(c *policy.Compiled, vols []winVolume, off bool) map[string]Destination {
	out := map[string]Destination{}
	if c == nil || off || !c.Modules.Files.CopyCorrelation.ScansOnClose() {
		return out
	}
	files := c.Modules.Files
	now := time.Now()
	e.wmu.Lock()
	defer e.wmu.Unlock()
	for root, until := range e.removing {
		if now.After(until) {
			delete(e.removing, root)
		}
	}
	for _, v := range vols {
		if !files.ChannelEnabled(v.Channel) || TrustedDevice(files.TrustedDevices, v.USB) || v.ReadOnly {
			continue
		}
		if _, ok := e.devices.madeRO[v.Source]; ok {
			continue // nothing can be written to it
		}
		if _, ok := e.removing[v.Mount]; ok {
			continue
		}
		out[v.Mount] = v.Destination
	}
	return out
}

// reconcileWatches starts watches for new monitored volumes and closes those
// no longer wanted (or whose volume went away).
func (e *windowsEnforcer) reconcileWatches(c *policy.Compiled, vols []winVolume, off bool) {
	want := e.monitoredVolumes(c, vols, off)
	e.wmu.Lock()
	var stale []string
	for root, we := range e.watches {
		if _, ok := want[root]; !ok || we.dead.Load() {
			stale = append(stale, root)
		}
	}
	e.wmu.Unlock()
	for _, root := range stale {
		e.releaseWatch(root)
	}
	for root, d := range want {
		e.wmu.Lock()
		_, have := e.watches[root]
		e.wmu.Unlock()
		if have {
			continue
		}
		e.addWatch(root, d)
	}
	e.wmu.Lock()
	list := make([]Destination, 0, len(e.watches))
	for _, we := range e.watches {
		list = append(list, we.dest)
	}
	e.wmu.Unlock()
	e.dests.Store(&list)
}

func (e *windowsEnforcer) addWatch(root string, d Destination) {
	we := &watchEntry{dest: d}
	changes := e.changes
	w, err := startWatch(root,
		func(ch fsChange) {
			select {
			case changes <- ch:
			default:
				e.dropped.Add(1)
			}
		},
		func(root string) {
			e.overflows.Add(1)
			select {
			case changes <- fsChange{root: root}: // rescan
			default:
			}
		},
		func(string) {
			we.dead.Store(true)
			select {
			case e.kick <- struct{}{}:
			default:
			}
		})
	if err != nil {
		log.Printf("DLP: can't watch a removable drive: %v", errnoOnly(err))
		return
	}
	we.w = w
	e.wmu.Lock()
	e.watches[root] = we
	e.wmu.Unlock()
	if err := devNotify.register(w.dir, func(removing bool) { e.deviceQuery(root, removing) }); err != nil {
		log.Printf("DLP: device removal notices unavailable: %v", err) // the drive may then report "in use" on eject
	}
}

// deviceQuery runs on the device window's thread: the user asked to remove
// root's drive (close the watch now, before answering, and leave the drive
// alone), or cancelled that.
func (e *windowsEnforcer) deviceQuery(root string, removing bool) {
	e.wmu.Lock()
	if removing {
		e.removing[root] = time.Now().Add(removeGrace)
	} else {
		delete(e.removing, root)
	}
	e.wmu.Unlock()
	if removing {
		e.releaseWatch(root)
	}
}

// releaseWatch closes root's watch, if there is one.
func (e *windowsEnforcer) releaseWatch(root string) {
	e.wmu.Lock()
	we := e.watches[root]
	delete(e.watches, root)
	e.wmu.Unlock()
	if we == nil || we.w == nil {
		return
	}
	devNotify.unregister(we.w.dir)
	we.w.close()
}

func (e *windowsEnforcer) offSwitch() bool {
	if e.opts.ConfigDir == "" {
		return false
	}
	_, err := os.Lstat(filepath.Join(e.opts.ConfigDir, OffSwitchFile))
	return err == nil
}

// pendingFile is a changed file waiting for its writer to finish.
type pendingFile struct {
	first, last time.Time
}

// pendingLoop collects changed files and queues each for a decision once it
// has been quiet and can be opened without write sharing.
func (e *windowsEnforcer) pendingLoop(ctx context.Context, changes <-chan fsChange, queue chan<- Request) {
	defer e.wg.Done()
	pending := map[string]*pendingFile{}
	t := time.NewTicker(pendingTick)
	defer t.Stop()
	add := func(path string, now time.Time) {
		if p, ok := pending[path]; ok {
			p.last = now
			return
		}
		if len(pending) >= maxPending {
			e.dropped.Add(1)
			return
		}
		pending[path] = &pendingFile{first: now, last: now}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ch := <-changes:
			if e.localOff.Load() {
				continue
			}
			if ch.path == "" {
				for _, p := range rescan(ch.root, time.Now().Add(-rescanWindow)) {
					add(p, time.Now())
				}
				continue
			}
			add(ch.path, time.Now())
		case now := <-t.C:
			for path, p := range pending {
				quiet := quietFor
				if isTempName(filepath.Base(path)) {
					quiet = tempQuietFor
				}
				if now.Sub(p.last) < quiet {
					continue
				}
				r, st := e.openChanged(path, now)
				switch st {
				case openRetry:
					if now.Sub(p.first) > pendingGiveUp {
						delete(pending, path)
						e.unreadable.Add(1)
					} else {
						p.last = now // look again after another quiet period
					}
				case openSkip:
					delete(pending, path)
				case openOK:
					delete(pending, path)
					select {
					case queue <- r:
					default:
						_ = r.File.Close()
						e.dropped.Add(1)
					}
				}
			}
		}
	}
}

// rescan lists the files under root changed since since (after a lost
// batch of notifications), at most maxRescanFiles.
func rescan(root string, since time.Time) []string {
	var out []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // skip what can't be read
		}
		if len(out) >= maxRescanFiles {
			return filepath.SkipAll
		}
		if d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil && fi.ModTime().After(since) {
				out = append(out, path)
			}
		}
		return nil
	})
	return out
}

type openStatus int

const (
	openOK openStatus = iota
	openRetry
	openSkip
)

// openChanged opens a changed file for its decision: read and delete
// access (delete, for on_close_violation), sharing reads and deletes but not
// writes, so it can't change while it is scanned. A writer still holding it
// makes the open fail with a sharing violation: try again later.
func (e *windowsEnforcer) openChanged(path string, now time.Time) (Request, openStatus) {
	dest, ok := e.destinationOf(path)
	if !ok {
		return Request{}, openSkip
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return Request{}, openSkip
	}
	const share = windows.FILE_SHARE_READ | windows.FILE_SHARE_DELETE
	flags := uint32(windows.FILE_FLAG_BACKUP_SEMANTICS | windows.FILE_FLAG_OPEN_REPARSE_POINT | fileFlagNoRecall)
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.DELETE, share, nil, windows.OPEN_EXISTING, flags, 0)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		h, err = windows.CreateFile(p, windows.GENERIC_READ, share, nil, windows.OPEN_EXISTING, flags, 0) // can't remove it, but can still record it
	}
	switch {
	case errors.Is(err, windows.ERROR_SHARING_VIOLATION), errors.Is(err, windows.ERROR_LOCK_VIOLATION):
		return Request{}, openRetry
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
		return Request{}, openSkip // gone again (a temp file renamed away, say)
	case err != nil:
		e.unreadable.Add(1)
		return Request{}, openSkip
	}
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		_ = windows.CloseHandle(h)
		e.unreadable.Add(1)
		return Request{}, openSkip
	}
	const skipAttrs = windows.FILE_ATTRIBUTE_DIRECTORY | windows.FILE_ATTRIBUTE_REPARSE_POINT | windows.FILE_ATTRIBUTE_OFFLINE | attrRecallOnOpen | attrRecallOnData
	if fi.FileAttributes&skipAttrs != 0 {
		_ = windows.CloseHandle(h)
		return Request{}, openSkip // folders, links, and cloud placeholders (reading those would download them)
	}
	id, err := handleIdentity(h)
	if err != nil {
		_ = windows.CloseHandle(h)
		e.unreadable.Add(1)
		return Request{}, openSkip
	}
	r := Request{File: os.NewFile(uintptr(h), path), Path: path, Dest: dest, Proc: consoleUser(), Ident: id, At: now}
	e.attribute(&r, e.compiled.Load())
	return r, openOK
}

// destinationOf maps a path to the watched volume containing it.
func (e *windowsEnforcer) destinationOf(path string) (Destination, bool) {
	for _, d := range *e.dests.Load() {
		root := strings.TrimSuffix(d.Mount, `\`) + `\`
		if len(path) >= len(root) && strings.EqualFold(path[:len(root)], root) {
			return d, true
		}
	}
	return Destination{}, false
}

func (e *windowsEnforcer) decideLoop(ctx context.Context, queue <-chan Request) {
	defer e.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case r := <-queue:
			e.decide(ctx, r)
		}
	}
}

func (e *windowsEnforcer) decide(ctx context.Context, r Request) {
	defer func() { _ = r.File.Close() }()
	if e.localOff.Load() {
		return
	}
	e.decider.Invalidate(r.Ident) // written again: older versions are stale
	dctx, cancel := context.WithTimeout(ctx, policy.MaxScanTimeout*time.Millisecond+10*time.Second)
	defer cancel()
	e.decider.Handle(dctx, r)
}

// consoleUser is who most likely wrote to a removable drive: the user at
// the console. Without process attribution (process_taint, #331) the
// writing program is unknown; the session id routes the notification to
// that user's helper.
func consoleUser() Process {
	s := windows.WTSGetActiveConsoleSessionId()
	if s == 0xFFFFFFFF {
		return Process{}
	}
	id := strconv.FormatUint(uint64(s), 10)
	return Process{UID: id, User: sessionUserName(s)}
}

var (
	wtsapi32                        = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformationW = wtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory               = wtsapi32.NewProc("WTSFreeMemory")

	sessionNamesMu sync.Mutex
	sessionNames   = map[uint32]sessionName{}
)

type sessionName struct {
	name string
	at   time.Time
}

const (
	wtsUserName   = 5
	wtsDomainName = 7
)

// sessionUserName is DOMAIN\user of a session, cached for a minute (a
// session id is reused after logoff).
func sessionUserName(s uint32) string {
	sessionNamesMu.Lock()
	defer sessionNamesMu.Unlock()
	if n, ok := sessionNames[s]; ok && time.Since(n.at) < time.Minute {
		return n.name
	}
	name := wtsString(s, wtsUserName)
	if dom := wtsString(s, wtsDomainName); dom != "" && name != "" {
		name = dom + `\` + name
	}
	if len(sessionNames) > 64 {
		clear(sessionNames)
	}
	sessionNames[s] = sessionName{name: name, at: time.Now()}
	return name
}

func wtsString(s uint32, class uintptr) string {
	var buf *uint16
	var n uint32
	r, _, _ := procWTSQuerySessionInformationW.Call(0, uintptr(s), class, uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n)))
	if r == 0 || buf == nil {
		return ""
	}
	defer func() { _, _, _ = procWTSFreeMemory.Call(uintptr(unsafe.Pointer(buf))) }()
	return windows.UTF16PtrToString(buf)
}

// windowsMethods are the copy correlation methods this hook implements ("")
// or why it can't: process_taint needs the ETW trace (64-bit Windows, admin).
func (e *windowsEnforcer) windowsMethods() map[string]string {
	m := map[string]string{
		MethodScanOnClose:      "",
		MethodUntrustedDevices: "",
		MethodProcessTaint:     "",
		MethodOSCopyEvents:     winMethodsNoOSCpy, // macOS's copyfile/clone events
	}
	if !etwAvailable {
		m[MethodProcessTaint] = "etw_unavailable"
	} else if r := e.taintError.Load(); r != nil {
		m[MethodProcessTaint] = *r
	}
	return m
}

func (e *windowsEnforcer) CopyCorrelation() map[string]string {
	e.mu.Lock()
	state, workers := e.stateLocked()
	e.mu.Unlock()
	if state == stateStopped {
		state = stateRunning
	}
	return copyCorrelationCapabilities(e.compiled.Load(), e.windowsMethods(), state, workers)
}

func (e *windowsEnforcer) Capabilities() map[string]string {
	e.mu.Lock()
	state, workers := e.stateLocked()
	e.mu.Unlock()
	return channelCapabilities(e.compiled.Load(), windowsChannels, state, workers)
}

func (e *windowsEnforcer) stateLocked() (string, scanworker.Health) {
	workers := e.lastPool
	if pool := e.pool.Load(); pool != nil {
		workers = pool.Health()
	}
	switch {
	case !e.running:
		return stateStopped, workers
	case e.localOff.Load():
		return stateLocalOff, workers
	default:
		return stateRunning, workers
	}
}

// Health has no Blocking part: Windows never holds a file (#330).
func (e *windowsEnforcer) Health() *Health {
	e.mu.Lock()
	state, workers := e.stateLocked()
	tried := e.tried
	e.mu.Unlock()
	if !tried {
		return nil
	}
	h := &Health{State: state, Mounts: len(*e.dests.Load()), Dropped: e.dropped.Load(), Overflows: e.overflows.Load(),
		Unreadable: e.unreadable.Load(), Stats: e.decider.Stats(), Workers: workers}
	if t := e.taint.Load(); t != nil {
		h.TaintProcesses = t.store.len()
		if t.sess != nil {
			_, h.TaintOverflows = t.sess.stats()
		}
	}
	return h
}
