package filedlp

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"os"
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

// Linux watches with fanotify *notification* events (FAN_CLOSE_WRITE on the
// mounts of removable media and network shares): the kernel reports a file
// after it was written and closed, and never waits for us. A slow, stuck or
// crashed agent therefore can't hang anything; at worst events are dropped
// (and counted). Blocking is a separate permission group with its own
// fail-safes (perm_linux.go, permgate.go), running only while a policy
// enforces block.

// linuxChannels are the file channels this hook monitors.
var linuxChannels = map[string]bool{policy.ChannelFileRemovable: true, policy.ChannelFileNetworkShare: true}

// Test seams: how a mount is classified, the scan workers' environment, the
// mount table, and the fanotify calls (so the loops run without root).
var (
	classifyMount = classify
	workerEnv     []string
	mountinfoPath = "/proc/self/mountinfo"
	fanotifyInit  = func() (int, error) {
		return unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK,
			unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
	}
	markMount = func(fan int, add bool, mountPoint string) error {
		flags := uint(unix.FAN_MARK_MOUNT)
		if add {
			flags |= unix.FAN_MARK_ADD
		} else {
			flags |= unix.FAN_MARK_REMOVE
		}
		return unix.FanotifyMark(fan, flags, unix.FAN_CLOSE_WRITE, unix.AT_FDCWD, mountPoint)
	}
)

// Tuning.
const (
	queueSize     = 256
	decideWorkers = 2
	mountPoll     = 2 * time.Second
	readPollMs    = 500
	// metaLen is sizeof(struct fanotify_event_metadata).
	metaLen = 24
)

type linuxEnforcer struct {
	opts    Options
	decider *Decider

	mu       sync.Mutex
	running  bool
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	fan      int
	queue    chan Request
	kick     chan struct{}
	failure  string                    // why the hook couldn't start ("" when it could)
	devices  *deviceState              // untrusted device control; the mount loop's, then stopLocked's
	taint    atomic.Pointer[taintHook] // process taint; nil when its group couldn't open
	tried    bool                      // start was attempted at least once (Health is reported from then on)
	lastPool scanworker.Health

	// pool is read by the decide loops, so it is atomic: they must never
	// take e.mu, which stopLocked holds while waiting for them.
	pool     atomic.Pointer[scanworker.Pool]
	compiled atomic.Pointer[policy.Compiled]
	dests    atomic.Pointer[[]Destination] // marked mounts, longest mount point first
	localOff atomic.Bool

	dropped, overflows, unreadable atomic.Uint64

	// The permission hook (blocking): owned by the mount loop.
	perm        atomic.Pointer[permHook]
	permFailure atomic.Pointer[string] // why blocking is off for good (until restart)
	lastPerm    atomic.Pointer[PermStats]
}

// New returns the Linux file DLP enforcer.
func New(o Options) Enforcer {
	e := &linuxEnforcer{opts: o, fan: -1, devices: newDeviceState()}
	e.decider = NewDecider(poolScanner{e}, o.Sink)
	e.decider.SetSourceOpener(openSource)
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

// poolScanner scans through the enforcer's current pool.
type poolScanner struct{ e *linuxEnforcer }

func (p poolScanner) Scan(ctx context.Context, f *os.File, size int64, timeout time.Duration) filescan.Result {
	pool := p.e.pool.Load()
	if pool == nil {
		return filescan.Result{Status: filescan.Unscannable(scanworker.ReasonWorkerFailed), Size: size}
	}
	return pool.Scan(ctx, f, size, timeout)
}

func (e *linuxEnforcer) Wants(m policy.FilesModule) bool { return wants(m, linuxChannels) }

func (e *linuxEnforcer) Apply(_ context.Context, c *policy.Compiled) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.compiled.Store(c)
	e.decider.Apply(c)
	if c == nil || !wants(c.Modules.Files, linuxChannels) {
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
	case e.kick <- struct{}{}: // re-mark now (channels or trusted lists may have changed)
	default:
	}
}

func (e *linuxEnforcer) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopLocked()
	e.compiled.Store(nil)
	e.decider.Apply(nil)
}

// startLocked opens the fanotify group and starts the loops. e.mu is held.
func (e *linuxEnforcer) startLocked() {
	e.tried = true
	fan, err := fanotifyInit()
	if err != nil {
		e.failure = fanotifyFailure(err)
		log.Printf("DLP: file monitoring unavailable: fanotify: %v", err)
		return
	}
	e.failure = ""
	e.permFailure.Store(nil) // a restart gives blocking another chance
	ctx, cancel := context.WithCancel(context.Background())
	e.fan, e.cancel, e.running = fan, cancel, true
	e.queue = make(chan Request, queueSize)
	e.kick = make(chan struct{}, 1)
	pool := scanworker.NewPool(scanworker.Options{Exe: e.opts.Exe, Env: workerEnv})
	if c := e.compiled.Load(); c != nil {
		if raw, err := json.Marshal(c.Bundle); err == nil {
			pool.SetPolicy(raw)
		}
	}
	e.pool.Store(pool)
	empty := []Destination{}
	e.dests.Store(&empty)
	e.wg.Add(2 + decideWorkers)
	go e.mountLoop(ctx, fan, e.kick)
	go e.readLoop(ctx, fan, e.queue)
	for i := 0; i < decideWorkers; i++ {
		go e.decideLoop(ctx, e.queue)
	}
	log.Printf("DLP: file monitoring started (audit only: removable media and network shares)")
}

// stopLocked stops the loops, closes the group (which removes every mark)
// and stops the workers. The loops never take e.mu, so waiting here is safe.
func (e *linuxEnforcer) stopLocked() {
	if !e.running {
		return
	}
	e.running = false
	e.cancel()
	e.wg.Wait()
	e.stopPerm() // after the mount loop: it owns the hook
	for {
		select {
		case r := <-e.queue:
			_ = r.File.Close()
			continue
		default:
		}
		break
	}
	_ = unix.Close(e.fan)
	e.fan = -1
	e.stopTaint()
	restoreDevices(e.devices) // fail open: nothing stays read-only because of us
	pool := e.pool.Swap(nil)
	e.lastPool = pool.Health()
	e.lastPool.Workers = 0 // stopped below; failures and the crash-loop flag are kept
	pool.Stop()
	empty := []Destination{}
	e.dests.Store(&empty)
	log.Printf("DLP: file monitoring stopped")
}

func fanotifyFailure(err error) string {
	switch {
	case errors.Is(err, unix.EPERM):
		return "unavailable:not_permitted"
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EINVAL):
		return "unavailable:fanotify_unavailable"
	default:
		return "unavailable:fanotify_error"
	}
}

// mountLoop keeps a mark on every monitored mount, and untrusted devices
// read-only when asked: on start, every mountPoll, and when kicked.
func (e *linuxEnforcer) mountLoop(ctx context.Context, fan int, kick <-chan struct{}) {
	defer e.wg.Done()
	marked := map[string]Destination{}
	failed := map[string]bool{}
	t := time.NewTicker(mountPoll)
	defer t.Stop()
	for {
		off := e.offSwitch()
		e.localOff.Store(off)
		c := e.compiled.Load()
		all := classifiedMounts()
		watch := e.monitoredMounts(c, all, off)
		e.reconcileMarks(fan, marked, failed, watch)
		e.reconcilePerm(c, off)
		e.reconcileTaint(ctx, c, len(watch) > 0)
		e.reconcileDevices(c, all, off, e.devices)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-kick:
		}
	}
}

// reconcileMarks adds marks for new monitored mounts and removes those of
// mounts no longer in want.
func (e *linuxEnforcer) reconcileMarks(fan int, marked map[string]Destination, failed map[string]bool, want map[string]Destination) {
	for mp := range marked {
		if _, ok := want[mp]; !ok {
			_ = markMount(fan, false, mp)
			delete(marked, mp)
		}
	}
	for mp, d := range want {
		if _, ok := marked[mp]; ok {
			marked[mp] = d
			continue
		}
		if err := markMount(fan, true, mp); err != nil {
			if !failed[mp] {
				failed[mp] = true
				log.Printf("DLP: can't watch %s mount: %v", d.Type, err) // the mount point may name a user; not logged
			}
			continue
		}
		delete(failed, mp)
		marked[mp] = d
	}
	list := make([]Destination, 0, len(marked))
	for _, d := range marked {
		list = append(list, d)
	}
	// Longest mount point first, so a file maps to its innermost mount.
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && len(list[j].Mount) > len(list[j-1].Mount); j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
	e.dests.Store(&list)
}

// classifiedMounts lists every mount that is a removable drive or a network
// share, from the mount table.
func classifiedMounts() []Destination {
	f, err := os.Open(mountinfoPath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	labels := volumeLabels()
	var out []Destination
	for _, m := range parseMountinfo(f) {
		if d, ok := classifyMount(m, labels); ok {
			out = append(out, d)
		}
	}
	return out
}

// monitoredMounts lists the mounts to watch under c: removable media and
// network shares whose channel is on, minus trusted devices and shares; none
// when scanning after the write is off or the emergency switch is on.
func (e *linuxEnforcer) monitoredMounts(c *policy.Compiled, all []Destination, off bool) map[string]Destination {
	out := map[string]Destination{}
	if c == nil || off || !c.Modules.Files.CopyCorrelation.ScansOnClose() {
		return out
	}
	files := c.Modules.Files
	for _, d := range all {
		if !files.ChannelEnabled(d.Channel) {
			continue
		}
		if TrustedDevice(files.TrustedDevices, d.USB) || TrustedShare(files.TrustedShares, d) {
			continue
		}
		out[d.Mount] = d
	}
	return out
}

func (e *linuxEnforcer) offSwitch() bool {
	if e.opts.ConfigDir == "" {
		return false
	}
	_, err := os.Lstat(filepath.Join(e.opts.ConfigDir, OffSwitchFile))
	return err == nil
}

// readLoop reads fanotify events and queues them; it never blocks on the
// queue (a full queue drops the event and counts it).
func (e *linuxEnforcer) readLoop(ctx context.Context, fan int, queue chan<- Request) {
	defer e.wg.Done()
	buf := make([]byte, 64<<10)
	self := os.Getpid()
	for ctx.Err() == nil {
		fds := []unix.PollFd{{Fd: int32(fan), Events: unix.POLLIN}} // #nosec G115 -- a descriptor
		if n, err := unix.Poll(fds, readPollMs); err != nil || n == 0 {
			continue
		}
		n, err := unix.Read(fan, buf)
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
			e.handleEvent(mask, fd, pid, self, queue)
		}
	}
}

func (e *linuxEnforcer) handleEvent(mask uint64, fd, pid, self int, queue chan<- Request) {
	if mask&unix.FAN_Q_OVERFLOW != 0 {
		e.overflows.Add(1)
	}
	if fd < 0 {
		if mask&unix.FAN_Q_OVERFLOW == 0 {
			e.unreadable.Add(1)
		}
		return
	}
	f := os.NewFile(uintptr(fd), "fanotify-event") // #nosec G115 -- checked >= 0
	if pid == self || e.localOff.Load() {
		_ = f.Close()
		return
	}
	path, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		_ = f.Close()
		e.unreadable.Add(1)
		return
	}
	dest, ok := e.destinationOf(path)
	if !ok {
		_ = f.Close()
		return
	}
	r := Request{File: f, Path: path, Dest: dest, Proc: processInfo(pid), At: time.Now()}
	select {
	case queue <- r:
	default:
		_ = f.Close()
		e.dropped.Add(1)
	}
}

// destinationOf maps a path to the innermost marked mount containing it.
func (e *linuxEnforcer) destinationOf(path string) (Destination, bool) {
	for _, d := range *e.dests.Load() {
		if path == d.Mount || strings.HasPrefix(path, strings.TrimSuffix(d.Mount, "/")+"/") {
			return d, true
		}
	}
	return Destination{}, false
}

// decideLoop decides queued events. Each has its own deadline, so one file
// can't hold a loop longer than its scan timeout plus the worker grace.
func (e *linuxEnforcer) decideLoop(ctx context.Context, queue <-chan Request) {
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

func (e *linuxEnforcer) decide(ctx context.Context, r Request) {
	defer func() { _ = r.File.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(int(r.File.Fd()), &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG { // #nosec G115 -- a descriptor
		return
	}
	r.Ident = Identity{Dev: st.Dev, Ino: st.Ino, Size: st.Size, ModTime: st.Mtim.Nano(), ChangeTime: st.Ctim.Nano()} // #nosec G115 -- device numbers
	if r.Proc.UID == "" {
		// The writer exited before we could look at it (cp often does): the
		// file's owner is the next best answer (on vfat, whoever mounted it).
		r.Proc.UID = strconv.FormatUint(uint64(st.Uid), 10)
		r.Proc.User = userName(r.Proc.UID)
	}
	e.decider.Invalidate(r.Ident) // written again: older versions are stale
	r.Sources = e.taintSources(e.compiled.Load(), r.Proc.PID)
	dctx, cancel := context.WithTimeout(ctx, policy.MaxScanTimeout*time.Millisecond+10*time.Second)
	defer cancel()
	e.decider.Handle(dctx, r)
}

// linuxMethods are the copy correlation methods this hook implements ("") or
// why it can't ("not_on_linux"). Missing ones are not implemented yet.
var linuxMethods = map[string]string{
	MethodScanOnClose:      "",
	MethodUntrustedDevices: "",
	MethodProcessTaint:     "",
	MethodOSCopyEvents:     "not_on_linux", // macOS's copyfile/clone events
}

func (e *linuxEnforcer) CopyCorrelation() map[string]string {
	e.mu.Lock()
	state, workers := e.stateLocked()
	e.mu.Unlock()
	if state == stateStopped {
		state = stateRunning // stopped by the settings, not unable: the method itself works here
	}
	return copyCorrelationCapabilities(e.compiled.Load(), linuxMethods, state, workers)
}

func (e *linuxEnforcer) Capabilities() map[string]string {
	e.mu.Lock()
	state, workers := e.stateLocked()
	e.mu.Unlock()
	caps := channelCapabilities(e.compiled.Load(), linuxChannels, state, workers)
	if state == stateRunning && len(caps) > 0 && e.opts.Notifier != nil {
		// a block_override block can ask its user for a reason (#336)
		caps[CapabilityBlockOverride] = "supported"
	}
	return caps
}

// stateLocked is the hook's state and the workers' health. e.mu is held.
func (e *linuxEnforcer) stateLocked() (string, scanworker.Health) {
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

func (e *linuxEnforcer) Health() *Health {
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
		t.mu.Lock()
		h.TaintOverflows = t.overflows
		t.mu.Unlock()
		h.TaintProcesses = t.store.len()
	}
	h.Blocking = e.blockingHealth()
	return h
}
