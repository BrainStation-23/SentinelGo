package scanworker

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// unprivilegedUsers are tried in order for the worker's account when the
// service runs as root.
var unprivilegedUsers = []string{"sentinelgo-scan", "nobody"}

// poolOS remembers that workers can't get a network namespace here, so
// later workers don't try again.
type poolOS struct{ noNetns bool }

// workerProc is a Linux worker's process.
type workerProc struct{ cmd *exec.Cmd }

// spawn starts a sandboxed worker and waits for its hello.
func (p *Pool) spawn() (*worker, error) {
	c, child, err := socketPair()
	if err != nil {
		return nil, err
	}
	cmd, err := p.command(child)
	if err != nil {
		_ = child.Close()
		_ = c.c.Close()
		return nil, err
	}
	p.mu.Lock()
	if p.osState.noNetns {
		cmd.SysProcAttr.Cloneflags = 0
	}
	p.mu.Unlock()
	err = cmd.Start()
	if errors.Is(err, syscall.EPERM) && cmd.SysProcAttr.Cloneflags != 0 {
		// Not allowed to create a network namespace (a container without
		// CAP_SYS_ADMIN, a hardened unit): run without one. Landlock still
		// denies TCP where the kernel supports it (ABI 4+).
		cmd, err = p.command(child)
		if err == nil {
			cmd.SysProcAttr.Cloneflags = 0
			err = cmd.Start()
		}
		if err == nil {
			p.mu.Lock()
			p.osState.noNetns = true
			p.mu.Unlock()
		}
	}
	if err != nil {
		_ = child.Close()
		_ = c.c.Close()
		return nil, fmt.Errorf("start scan worker: %w", err)
	}
	_ = child.Close()
	w := &worker{c: c, proc: workerProc{cmd: cmd}, exited: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(w.exited) }()

	desc, err := awaitReady(w)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.all[w] = struct{}{}
	p.sandbox = desc
	if cred := cmd.SysProcAttr.Credential; cred != nil {
		p.sandbox += ",user=" + strconv.FormatUint(uint64(cred.Uid), 10)
	}
	if cmd.SysProcAttr.Cloneflags&syscall.CLONE_NEWNET != 0 {
		p.sandbox += ",netns"
	}
	p.mu.Unlock()
	return w, nil
}

// command builds a worker's command with child as its fd 3. As root the
// worker runs as an unprivileged account in a new network namespace; it dies
// with the service.
func (p *Pool) command(child *os.File) (*exec.Cmd, error) {
	cmd := exec.Command(p.opts.Exe, p.opts.Args...) // #nosec G204 -- our own binary
	cmd.ExtraFiles = []*os.File{child}
	cmd.Env = p.opts.Env
	if cmd.Env == nil {
		cmd.Env = []string{}
	}
	cmd.Dir = "/"
	attr := &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if os.Geteuid() == 0 {
		ensureScanAccount()
		uid, gid, err := unprivilegedIDs()
		if err != nil {
			return nil, err
		}
		attr.Credential = &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}
		attr.Cloneflags = syscall.CLONE_NEWNET
	}
	cmd.SysProcAttr = attr
	return cmd, nil
}

// unprivilegedIDs resolves the worker's account.
func unprivilegedIDs() (uint32, uint32, error) {
	for _, name := range unprivilegedUsers {
		u, err := user.Lookup(name)
		if err != nil {
			continue
		}
		uid, err1 := strconv.ParseUint(u.Uid, 10, 32)
		gid, err2 := strconv.ParseUint(u.Gid, 10, 32)
		if err1 == nil && err2 == nil && uid != 0 {
			return uint32(uid), uint32(gid), nil
		}
	}
	return 0, 0, errors.New("no unprivileged account for scan workers (tried sentinelgo-scan, nobody)")
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

// socketpairCloexec makes the service<->worker socket pair, close-on-exec.
func socketpairCloexec() ([2]int, error) {
	return unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
}
