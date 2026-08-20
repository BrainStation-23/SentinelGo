package task

import (
	"bytes"
	"os/exec"
)

const maxTaskOutputBytes = 1024 * 1024

type boundedTaskOutput struct {
	buf       bytes.Buffer
	remaining int
	truncated bool
}

func newBoundedTaskOutput(limit int) *boundedTaskOutput {
	return &boundedTaskOutput{remaining: limit}
}

func (w *boundedTaskOutput) Write(p []byte) (int, error) {
	original := len(p)
	if len(p) > w.remaining {
		p = p[:w.remaining]
		w.truncated = true
	}
	if len(p) > 0 {
		_, _ = w.buf.Write(p)
		w.remaining -= len(p)
	}
	return original, nil
}

func (w *boundedTaskOutput) String() string {
	if w.truncated {
		return w.buf.String() + "\n[output truncated at 1 MiB]"
	}
	return w.buf.String()
}

// runCommandBounded captures the merged stdout/stderr stream without allowing
// a privileged script to consume unbounded agent memory or database storage.
// Output is returned to the authenticated task result path, never written to
// the local application log.
func runCommandBounded(cmd *exec.Cmd) (string, error) {
	out := newBoundedTaskOutput(maxTaskOutputBytes)
	cmd.Stdout = out
	cmd.Stderr = out
	err := cmd.Run()
	return out.String(), err
}
