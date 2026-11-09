package filedlp

// macOS file DLP in the Go daemon, without a system extension (#332):
//
//   - layer 1: every removable volume and network share is watched with
//     FSEvents (through purego); a file is scanned in the sandboxed workers
//     once it has been quiet, and on_close_violation records, quarantines or
//     deletes it;
//   - layer 2: untrusted removable volumes are mounted read-only again with
//     diskutil (copy_correlation.untrusted_devices).
//
// Blocking a copy before it lands needs Endpoint Security (layer 3), which
// needs Apple's entitlement (#325); until then macOS detects and removes,
// like Windows. Nothing here waits on the agent.

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"sentinelgo/internal/dlp/filescan"
	"sentinelgo/internal/dlp/policy"
	"sentinelgo/internal/dlp/scanworker"
)

// darwinChannels are the file channels this hook monitors.
var darwinChannels = map[string]bool{policy.ChannelFileRemovable: true, policy.ChannelFileNetworkShare: true}

// workerEnv is extra environment for the scan workers (tests).
var workerEnv []string

// Test seam: what watches a root.
var startRootWatch = func(root string, change func(fsChange), overflow, gone func(string)) (watchCloser, error) {
	return startFSEvents(root, change, overflow, gone)
}

type watchCloser interface{ close() }

var volumePoll = 2 * time.Second

const (
	macQueueSize     = 256
	macDecideWorkers = 2
	sfDataless       = 0x40000000 // SF_DATALESS: a File Provider placeholder
	// esReason is why the methods that need Endpoint Security can't run yet.
	esReason = "needs_endpoint_security"
)

type darwinEnforcer struct {
	opts    Options
	decider *Decider

	mu       sync.Mutex
	running  bool
	tried    bool
	failure  string
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	queue    chan Request
	changes  chan fsChange
	kick     chan struct{}
	devices  *deviceCtl
	lastPool scanworker.Health

	pool     atomic.Pointer[scanworker.Pool]
	compiled atomic.Pointer[policy.Compiled]
	dests    atomic.Pointer[[]Destination]
	localOff atomic.Bool

	dropped, overflows, unreadable atomic.Uint64

	wmu     sync.Mutex
	watches map[string]*macWatch
}

type macWatch struct {
	w    watchCloser
	dest Destination
	dead atomic.Bool
}

// New returns the macOS file DLP enforcer.
func New(o Options) Enforcer {
	e := &darwinEnforcer{opts: o, watches: map[string]*macWatch{}}
	e.devices = newDeviceCtl(o.Sink, setReadOnlyDevice, e.releaseWatch)
	e.decider = NewDecider(macPoolScanner{e}, o.Sink)
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

type macPoolScanner struct{ e *darwinEnforcer }

func (p macPoolScanner) Scan(ctx context.Context, f *os.File, size int64, timeout time.Duration) filescan.Result {
	pool := p.e.pool.Load()
	if pool == nil {
		return filescan.Result{Status: filescan.Unscannable(scanworker.ReasonWorkerFailed), Size: size}
	}
	return pool.Scan(ctx, f, size, timeout)
}

func (e *darwinEnforcer) Wants(m policy.FilesModule) bool { return wants(m, darwinChannels) }

func (e *darwinEnforcer) Apply(_ context.Context, c *policy.Compiled) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.compiled.Store(c)
	e.decider.Apply(c)
	if c == nil || !wants(c.Modules.Files, darwinChannels) {
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

func (e *darwinEnforcer) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopLocked()
	e.compiled.Store(nil)
	e.decider.Apply(nil)
}

func (e *darwinEnforcer) startLocked() {
	e.tried = true
	e.failure = ""
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel, e.running = cancel, true
	e.queue = make(chan Request, macQueueSize)
	e.changes = make(chan fsChange, changeQueueSize)
	e.kick = make(chan struct{}, 1)
	pool := scanworker.NewPool(scanworker.Options{Exe: e.opts.Exe, Env: workerEnv})
	if c := e.compiled.Load(); c != nil {
		if raw, err := json.Marshal(c.Bundle); err == nil {
			pool.SetPolicy(raw)
		}
	}
	e.pool.Store(pool)
	e.wg.Add(2 + macDecideWorkers)
	go e.volumeLoop(ctx, e.kick)
	go e.pendingLoop(ctx, e.changes, e.queue)
	for i := 0; i < macDecideWorkers; i++ {
		go e.decideLoop(ctx, e.queue)
	}
	log.Printf("DLP: file monitoring started (removable drives and network shares: scanned after the write)")
}

func (e *darwinEnforcer) stopLocked() {
	if !e.running {
		return
	}
	e.running = false
	e.cancel()
	e.wg.Wait()
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
	e.devices.restore()
	pool := e.pool.Swap(nil)
	e.lastPool = pool.Health()
	e.lastPool.Workers = 0
	pool.Stop()
	empty := []Destination{}
	e.dests.Store(&empty)
	log.Printf("DLP: file monitoring stopped")
}

func (e *darwinEnforcer) volumeLoop(ctx context.Context, kick <-chan struct{}) {
	defer e.wg.Done()
	t := time.NewTicker(volumePoll)
	defer t.Stop()
	for {
		off := e.offSwitch()
		e.localOff.Store(off)
		c := e.compiled.Load()
		vols := listVolumes()
		e.devices.reconcile(c, devVolumes(vols), off)
		e.reconcileWatches(c, vols, off)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-kick:
		}
	}
}

// monitoredVolumes are the mounts to watch under c: removable volumes and
// network shares whose channel is on, not trusted and writable; none when
// scanning after the write is off or the emergency switch is on.
func (e *darwinEnforcer) monitoredVolumes(c *policy.Compiled, vols []macVolume, off bool) map[string]Destination {
	out := map[string]Destination{}
	if c == nil || off || !c.Modules.Files.CopyCorrelation.ScansOnClose() {
		return out
	}
	files := c.Modules.Files
	for _, v := range vols {
		if !files.ChannelEnabled(v.Channel) || v.ReadOnly || TrustedDevice(files.TrustedDevices, v.USB) || TrustedShare(files.TrustedShares, v.Destination) {
			continue
		}
		if e.devices.madeReadOnly(v.Source) {
			continue
		}
		out[v.Mount] = v.Destination
	}
	return out
}

func (e *darwinEnforcer) reconcileWatches(c *policy.Compiled, vols []macVolume, off bool) {
	want := e.monitoredVolumes(c, vols, off)
	e.wmu.Lock()
	var stale []string
	for root, mw := range e.watches {
		if _, ok := want[root]; !ok || mw.dead.Load() {
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
		if !have {
			e.addWatch(root, d)
		}
	}
	e.wmu.Lock()
	list := make([]Destination, 0, len(e.watches))
	for _, mw := range e.watches {
		list = append(list, mw.dest)
	}
	e.wmu.Unlock()
	// Longest mount point first, so a file maps to its innermost mount.
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && len(list[j].Mount) > len(list[j-1].Mount); j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
	e.dests.Store(&list)
}

func (e *darwinEnforcer) addWatch(root string, d Destination) {
	mw := &macWatch{dest: d}
	changes := e.changes
	w, err := startRootWatch(root,
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
			case changes <- fsChange{root: root}:
			default:
			}
		},
		func(string) {
			mw.dead.Store(true)
			select {
			case e.kick <- struct{}{}:
			default:
			}
		})
	if err != nil {
		e.mu.Lock()
		e.failure = "unavailable:fsevents_unavailable"
		e.mu.Unlock()
		log.Printf("DLP: can't watch a %s: %v", d.Type, err)
		return
	}
	mw.w = w
	e.wmu.Lock()
	e.watches[root] = mw
	e.wmu.Unlock()
}

func (e *darwinEnforcer) releaseWatch(root string) {
	e.wmu.Lock()
	mw := e.watches[root]
	delete(e.watches, root)
	e.wmu.Unlock()
	if mw != nil && mw.w != nil {
		mw.w.close()
	}
}

func (e *darwinEnforcer) offSwitch() bool {
	if e.opts.ConfigDir == "" {
		return false
	}
	_, err := os.Lstat(filepath.Join(e.opts.ConfigDir, OffSwitchFile))
	return err == nil
}

func (e *darwinEnforcer) pendingLoop(ctx context.Context, changes <-chan fsChange, queue chan<- Request) {
	defer e.wg.Done()
	pending := newPendingSet(&e.dropped, &e.unreadable)
	t := time.NewTicker(pendingTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ch := <-changes:
			if !e.localOff.Load() {
				pending.add(ch, time.Now())
			}
		case now := <-t.C:
			pending.due(now, e.openChanged, queue)
		}
	}
}

// openChanged opens a changed file for its decision, read-only and without
// following a link. FSEvents doesn't say whether a writer is done, so a file
// whose size or modification time moved since the event is looked at again
// after another quiet period.
func (e *darwinEnforcer) openChanged(path string, now time.Time) (Request, openStatus) {
	dest, ok := e.destinationOf(path)
	if !ok {
		return Request{}, openSkip
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if err == unix.ENOENT || err == unix.ELOOP {
			return Request{}, openSkip
		}
		e.unreadable.Add(1)
		return Request{}, openSkip
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Flags&sfDataless != 0 {
		_ = unix.Close(fd)
		return Request{}, openSkip // not a regular file, or a placeholder (reading it would download it)
	}
	if now.Sub(time.Unix(st.Mtim.Unix())) < quietFor {
		_ = unix.Close(fd)
		return Request{}, openRetry // still being written
	}
	id := Identity{Dev: uint64(st.Dev), Ino: st.Ino, Size: st.Size, ModTime: st.Mtim.Nano(), ChangeTime: st.Ctim.Nano()} // #nosec G115 -- a device number
	return Request{File: os.NewFile(uintptr(fd), path), Path: path, Dest: dest, Proc: consoleUserDarwin(), Ident: id, At: now}, openOK
}

func (e *darwinEnforcer) destinationOf(path string) (Destination, bool) {
	for _, d := range *e.dests.Load() {
		if path == d.Mount || strings.HasPrefix(path, strings.TrimSuffix(d.Mount, "/")+"/") {
			return d, true
		}
	}
	return Destination{}, false
}

func (e *darwinEnforcer) decideLoop(ctx context.Context, queue <-chan Request) {
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

func (e *darwinEnforcer) decide(ctx context.Context, r Request) {
	defer func() { _ = r.File.Close() }()
	if e.localOff.Load() {
		return
	}
	e.decider.Invalidate(r.Ident)
	dctx, cancel := context.WithTimeout(ctx, policy.MaxScanTimeout*time.Millisecond+10*time.Second)
	defer cancel()
	e.decider.Handle(dctx, r)
}

// consoleUserDarwin is the user at the console (who owns /dev/console):
// FSEvents doesn't say which program wrote a file. The uid routes the
// notification to that user's session helper.
func consoleUserDarwin() Process {
	var st unix.Stat_t
	if unix.Stat("/dev/console", &st) != nil || st.Uid == 0 {
		return Process{}
	}
	uid := strconv.FormatUint(uint64(st.Uid), 10)
	name := uid
	if u, err := user.LookupId(uid); err == nil {
		name = u.Username
	}
	return Process{UID: uid, User: name}
}

// darwinMethods: process taint and OS copy events need Endpoint Security
// (layer 3, #332), which needs Apple's entitlement.
var darwinMethods = map[string]string{
	MethodScanOnClose:      "",
	MethodUntrustedDevices: "",
	MethodProcessTaint:     esReason,
	MethodOSCopyEvents:     esReason,
}

func (e *darwinEnforcer) CopyCorrelation() map[string]string {
	e.mu.Lock()
	state, workers := e.stateLocked()
	e.mu.Unlock()
	if state == stateStopped {
		state = stateRunning
	}
	return copyCorrelationCapabilities(e.compiled.Load(), darwinMethods, state, workers)
}

func (e *darwinEnforcer) Capabilities() map[string]string {
	e.mu.Lock()
	state, workers := e.stateLocked()
	e.mu.Unlock()
	return channelCapabilities(e.compiled.Load(), darwinChannels, state, workers)
}

func (e *darwinEnforcer) stateLocked() (string, scanworker.Health) {
	workers := e.lastPool
	if pool := e.pool.Load(); pool != nil {
		workers = pool.Health()
	}
	switch {
	case e.failure != "":
		return e.failure, workers
	case !e.running:
		return stateStopped, workers
	case e.localOff.Load():
		return stateLocalOff, workers
	default:
		return stateRunning, workers
	}
}

// Health has no Blocking part until Endpoint Security (#332 layer 3).
func (e *darwinEnforcer) Health() *Health {
	e.mu.Lock()
	state, workers := e.stateLocked()
	tried := e.tried
	e.mu.Unlock()
	if !tried {
		return nil
	}
	return &Health{State: state, Mounts: len(*e.dests.Load()), Dropped: e.dropped.Load(), Overflows: e.overflows.Load(),
		Unreadable: e.unreadable.Load(), Stats: e.decider.Stats(), Workers: workers}
}
