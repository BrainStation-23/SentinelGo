//go:build linux || windows || darwin

package scanworker

// The pool's scheduling, the same on every OS that runs workers: start up to
// Workers sandboxed workers on demand, send each its policy, hand it one file
// at a time, kill one that doesn't answer in time, and stop starting new ones
// after repeated failures. pool_<os>.go starts the workers, hands them files
// and kills them.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"sentinelgo/internal/dlp/filescan"
)

// Pool defaults.
const (
	DefaultWorkers = 2
	// readyTimeout bounds a new worker's start-up (exec, sandbox, hello).
	readyTimeout = 10 * time.Second
	// scanGrace is added to the scan's own timeout before the worker is
	// presumed stuck and killed.
	scanGrace = 2 * time.Second
	// A crash loop: this many failures within crashWindow disable the pool.
	crashLimit  = 5
	crashWindow = 10 * time.Minute
)

// Options configure a Pool.
type Options struct {
	Exe     string   // the agent binary (os.Executable())
	Args    []string // default: [Command]
	Workers int      // default: DefaultWorkers
	Env     []string // the worker's environment (default: none beyond what the OS needs)
}

// Pool runs scans in sandboxed workers. It is safe for concurrent use.
type Pool struct {
	opts Options

	mu       sync.Mutex
	bundle   []byte
	version  uint64
	live     int
	all      map[*worker]struct{}
	stopped  bool
	disabled bool
	failures []time.Time
	total    int
	sandbox  string
	idle     chan *worker
	// changed is closed (and replaced) whenever a worker slot frees up, so
	// scans waiting for a worker try again instead of waiting forever.
	changed chan struct{}
	// osState is what the OS's spawn keeps between workers.
	osState poolOS
}

type worker struct {
	c       frameConn
	proc    workerProc // the OS process
	version uint64     // of the policy it has
	nextID  uint64
	exited  chan struct{}
}

// NewPool returns a pool; workers start on the first scan.
func NewPool(o Options) *Pool {
	if o.Workers <= 0 {
		o.Workers = DefaultWorkers
	}
	if len(o.Args) == 0 {
		o.Args = []string{Command}
	}
	return &Pool{opts: o, all: map[*worker]struct{}{}, idle: make(chan *worker, o.Workers), changed: make(chan struct{})}
}

// SetPolicy sets the bundle workers scan with; each worker gets it before
// its next scan.
func (p *Pool) SetPolicy(bundle []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bundle = append([]byte(nil), bundle...)
	p.version++
}

// Scan scans f (size bytes) in a worker. timeout is the scan's own limit; a
// worker that hasn't answered by then plus a grace period is killed and the
// result is a timeout. f stays open; the caller closes it.
func (p *Pool) Scan(ctx context.Context, f *os.File, size int64, timeout time.Duration) filescan.Result {
	failed := filescan.Result{Status: filescan.Unscannable(ReasonWorkerFailed), Size: size}
	w, err := p.acquire(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return filescan.Result{Status: filescan.StatusTimeout, Size: size}
		}
		return failed
	}
	res, err := p.scanIn(ctx, w, f, size, timeout)
	if err != nil {
		p.discard(w, !errors.Is(err, errScanTimeout))
		if errors.Is(err, errScanTimeout) {
			return filescan.Result{Status: filescan.StatusTimeout, Size: size}
		}
		return failed
	}
	p.release(w)
	return res
}

var errScanTimeout = errors.New("scan timed out")

func (p *Pool) scanIn(ctx context.Context, w *worker, f *os.File, size int64, timeout time.Duration) (filescan.Result, error) {
	p.mu.Lock()
	bundle, version := p.bundle, p.version
	p.mu.Unlock()
	if w.version != version {
		if err := w.c.writeMsg(message{Type: typePolicy, Bundle: bundle}, -1); err != nil {
			return filescan.Result{}, err
		}
		w.version = version
	}
	w.nextID++
	id := w.nextID
	if err := w.sendScan(message{Type: typeScan, ID: id, Size: size}, f); err != nil {
		return filescan.Result{}, err
	}
	deadline := time.Now().Add(timeout + scanGrace)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = w.c.setReadDeadline(deadline)
	// Cancelling ctx (the service stopping file DLP) ends the wait at once.
	stop := context.AfterFunc(ctx, func() { _ = w.c.setReadDeadline(time.Now()) })
	defer func() {
		stop()
		_ = w.c.setReadDeadline(time.Time{})
	}()
	m, extra, err := w.c.readMsg(maxFrameFromWorker)
	if extra != nil {
		_ = extra.Close()
	}
	if err != nil {
		if os.IsTimeout(err) {
			return filescan.Result{}, errScanTimeout
		}
		return filescan.Result{}, err
	}
	if m.Type != typeResult || m.ID != id || m.Result == nil {
		return filescan.Result{}, fmt.Errorf("scanworker: unexpected %q reply", m.Type)
	}
	return *m.Result, nil
}

// awaitReady waits for a new worker's hello and returns what its sandbox
// applies; on failure the worker is killed.
func awaitReady(w *worker) (string, error) {
	_ = w.c.setReadDeadline(time.Now().Add(readyTimeout))
	m, extra, err := w.c.readMsg(maxFrameFromWorker)
	_ = w.c.setReadDeadline(time.Time{})
	if extra != nil {
		_ = extra.Close()
	}
	if err != nil || m.Type != typeReady {
		w.kill()
		return "", fmt.Errorf("scan worker didn't start: %v", err)
	}
	return m.Sandbox, nil
}

// acquire returns an idle worker, starting one if fewer than the pool size
// are running. When none is free it waits for one, or for a slot to free up
// (a worker died or failed to start), or for ctx.
func (p *Pool) acquire(ctx context.Context) (*worker, error) {
	for {
		select {
		case w := <-p.idle:
			return w, nil
		default:
		}
		p.mu.Lock()
		switch {
		case p.stopped:
			p.mu.Unlock()
			return nil, errors.New("scanworker: pool stopped")
		case p.disabled:
			p.mu.Unlock()
			return nil, errors.New("scanworker: disabled after repeated failures")
		case p.live < p.opts.Workers:
			p.live++
			p.mu.Unlock()
			w, err := p.spawn()
			if err != nil {
				p.mu.Lock()
				p.live--
				p.failLocked(err)
				p.signalLocked()
				p.mu.Unlock()
				return nil, err
			}
			return w, nil
		}
		changed := p.changed
		p.mu.Unlock()
		select {
		case w := <-p.idle:
			return w, nil
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// signalLocked wakes the scans waiting in acquire. p.mu is held.
func (p *Pool) signalLocked() {
	close(p.changed)
	p.changed = make(chan struct{})
}

func (p *Pool) release(w *worker) {
	p.mu.Lock()
	stopped := p.stopped
	p.mu.Unlock()
	if stopped {
		p.discard(w, false)
		return
	}
	p.idle <- w // never blocks: at most opts.Workers workers exist
}

// discard kills w; failed counts it towards the crash-loop limit.
func (p *Pool) discard(w *worker, failed bool) {
	w.kill()
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.all[w]; ok {
		delete(p.all, w)
		p.live--
	}
	if failed {
		p.failLocked(errors.New("worker failed"))
	}
	p.signalLocked()
}

// failLocked records a failure and disables the pool on a crash loop.
func (p *Pool) failLocked(err error) {
	now := time.Now()
	p.total++
	keep := p.failures[:0]
	for _, t := range p.failures {
		if now.Sub(t) < crashWindow {
			keep = append(keep, t)
		}
	}
	p.failures = append(keep, now)
	if len(p.failures) >= crashLimit && !p.disabled {
		p.disabled = true
		log.Printf("DLP: file scan workers failed %d times in %v; file scanning is off until the agent restarts (last: %v)",
			len(p.failures), crashWindow, err)
	}
}

// Stop kills every worker. Scans in progress return worker_failed.
func (p *Pool) Stop() {
	p.mu.Lock()
	p.stopped = true
	workers := make([]*worker, 0, len(p.all))
	for w := range p.all {
		workers = append(workers, w)
	}
	p.all = map[*worker]struct{}{}
	p.live = 0
	p.signalLocked()
	p.mu.Unlock()
	for _, w := range workers {
		w.kill()
	}
	for {
		select {
		case <-p.idle:
		default:
			return
		}
	}
}

// Health reports the pool's state.
func (p *Pool) Health() Health {
	p.mu.Lock()
	defer p.mu.Unlock()
	return Health{Workers: p.live, Sandbox: p.sandbox, Failures: p.total, Disabled: p.disabled}
}
