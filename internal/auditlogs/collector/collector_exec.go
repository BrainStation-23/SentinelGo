//go:build linux || darwin

package collector

import (
	"context"
	"io"
	"os/exec"
)

// streamOpener starts a command and returns its stdout as a ReadCloser. Closing
// the ReadCloser terminates the command. It is the seam that makes the Unix
// collectors testable: production wires execStream; tests inject canned output
// (e.g. io.NopCloser around recorded `journalctl`/`log show` bytes).
type streamOpener func(ctx context.Context, name string, args ...string) (io.ReadCloser, error)

// execStream runs name+args and streams stdout. Closing the returned ReadCloser
// cancels the process context and waits for it to exit, so an early reader stop
// (e.g. after hitting the per-cycle cap) does not leak the subprocess.
func execStream(ctx context.Context, name string, args ...string) (io.ReadCloser, error) {
	cmdCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(cmdCtx, name, args...) // #nosec G204 -- name is always a hardcoded system binary at every call site

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, err
	}

	return &cmdStream{stdout: stdout, cancel: cancel, wait: cmd.Wait}, nil
}

// cmdStream adapts a running command's stdout into an io.ReadCloser whose Close
// reliably terminates and reaps the process.
type cmdStream struct {
	stdout io.ReadCloser
	cancel context.CancelFunc
	wait   func() error
}

func (c *cmdStream) Read(p []byte) (int, error) { return c.stdout.Read(p) }

func (c *cmdStream) Close() error {
	c.cancel()
	_ = c.stdout.Close()
	_ = c.wait()
	return nil
}
