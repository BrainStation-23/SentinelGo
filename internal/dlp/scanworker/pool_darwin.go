package scanworker

// macOS workers (#332, #412). As root the service starts each worker as the
// unprivileged ScanAccount (falling back to nobody), in its own process
// group, with the worker's end of a socket pair as fd 3; the worker then
// puts itself under a sandbox profile before it reads anything
// (worker_darwin.go). Profiles are tried strictest first, and the level
// that worked is kept for later workers (like the Windows levels):
//
//	0: pure-computation: no files by path, no network
//	1: no-network
//	2: no profile (the account and resource limits only)
//
// A worker whose hello never arrives (its profile broke the socket, say)
// counts as not started at that level. The level reached is reported in
// Health.Sandbox. Files arrive as descriptors (SCM_RIGHTS); the worker
// never opens a path. A worker exits when the service's end of the socket
// closes (macOS has no parent-death signal).

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Sandbox levels, passed to the worker in sandboxLevelEnv.
const (
	levelPureComputation = iota
	levelNoNetwork
	levelNoProfile
	levelCount

	sandboxLevelEnv = "SENTINELGO_SCAN_SANDBOX"
)

type poolOS struct{ level int }

type workerProc struct{ cmd *exec.Cmd }

// spawn starts a worker at the pool's level, dropping to the next level when
// one doesn't come up.
func (p *Pool) spawn() (*worker, error) {
	p.mu.Lock()
	level := p.osState.level
	p.mu.Unlock()
	var lastErr error
	for ; level < levelCount; level++ {
		w, desc, err := p.spawnAt(level)
		if err != nil {
			lastErr = err
			continue
		}
		p.mu.Lock()
		p.osState.level = level
		p.all[w] = struct{}{}
		p.sandbox = desc
		if cred := w.proc.cmd.SysProcAttr.Credential; cred != nil {
			p.sandbox += ",user=" + strconv.FormatUint(uint64(cred.Uid), 10)
		}
		p.mu.Unlock()
		return w, nil
	}
	return nil, lastErr
}

func (p *Pool) spawnAt(level int) (*worker, string, error) {
	c, child, err := socketPair()
	if err != nil {
		return nil, "", err
	}
	cmd, err := p.command(child, level)
	if err != nil {
		_ = child.Close()
		_ = c.c.Close()
		return nil, "", err
	}
	if err := cmd.Start(); err != nil {
		_ = child.Close()
		_ = c.c.Close()
		return nil, "", fmt.Errorf("start scan worker: %w", err)
	}
	_ = child.Close()
	w := &worker{c: c, proc: workerProc{cmd: cmd}, exited: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(w.exited) }()
	desc, err := awaitReady(w)
	if err != nil {
		w.kill()
		return nil, "", err
	}
	return w, desc, nil
}

// command builds a worker's command with child as its fd 3.
func (p *Pool) command(child *os.File, level int) (*exec.Cmd, error) {
	cmd := exec.Command(p.opts.Exe, p.opts.Args...) // #nosec G204 -- our own binary
	cmd.ExtraFiles = []*os.File{child}
	cmd.Env = append(append([]string{}, p.opts.Env...), sandboxLevelEnv+"="+strconv.Itoa(level))
	cmd.Dir = "/"
	attr := &syscall.SysProcAttr{Setpgid: true}
	if os.Geteuid() == 0 {
		ensureScanAccount()
		uid, gid, err := unprivilegedIDs()
		if err != nil {
			return nil, err
		}
		attr.Credential = &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}
	}
	cmd.SysProcAttr = attr
	return cmd, nil
}

// sendScan sends a scan request with f's descriptor alongside.
func (w *worker) sendScan(m message, f *os.File) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var werr error
	if cerr := rc.Control(func(fd uintptr) {
		werr = w.c.writeMsg(m, int(fd)) // #nosec G115 -- a descriptor
	}); cerr != nil {
		return cerr
	}
	return werr
}

func (w *worker) kill() {
	_ = w.c.close()
	if w.proc.cmd.Process != nil {
		_ = w.proc.cmd.Process.Kill()
	}
	select {
	case <-w.exited:
	case <-time.After(5 * time.Second):
	}
}

// socketpairCloexec makes the socket pair; macOS has no SOCK_CLOEXEC, so
// close-on-exec is set right after, under the fork lock.
func socketpairCloexec() ([2]int, error) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return fds, err
	}
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])
	return fds, nil
}
