package netctl

// With puts the Controller next to the file DLP enforcer, as the one
// filedlp.Enforcer the DLP Manager drives (like uploadproxy.WithUploads):
// the controls' capabilities join the file channels', and their status goes
// in the files health as network_control.

import (
	"context"
	"strings"

	"sentinelgo/internal/dlp/filedlp"
	"sentinelgo/internal/dlp/ipc"
	"sentinelgo/internal/dlp/policy"
)

type withControls struct {
	files filedlp.Enforcer // may be nil
	ctl   *Controller
}

// With returns an Enforcer that runs files (may be nil) and ctl.
func With(files filedlp.Enforcer, ctl *Controller) filedlp.Enforcer {
	return &withControls{files: files, ctl: ctl}
}

func (w *withControls) Wants(m policy.FilesModule) bool {
	return w.ctl.Wants(m) || w.files != nil && w.files.Wants(m)
}

func (w *withControls) Apply(ctx context.Context, c *policy.Compiled) {
	if w.files != nil {
		w.files.Apply(ctx, c)
	}
	w.ctl.Apply(ctx, c)
}

func (w *withControls) Stop() {
	if w.files != nil {
		w.files.Stop()
	}
	w.ctl.Stop()
}

func (w *withControls) Capabilities() map[string]string {
	var caps map[string]string
	if w.files != nil {
		caps = w.files.Capabilities()
	}
	extra := w.ctl.Capabilities()
	if len(extra) == 0 {
		return caps
	}
	out := make(map[string]string, len(caps)+len(extra))
	for k, v := range caps {
		out[k] = v
	}
	for k, v := range extra {
		if k == CapTaintBlock && strings.HasPrefix(caps[k], "unsupported:") {
			continue // the file hook knows why taint blocks can't run (no trace)
		}
		out[k] = v
	}
	return out
}

func (w *withControls) CopyCorrelation() map[string]string {
	if w.files == nil {
		return nil
	}
	return w.files.CopyCorrelation()
}

func (w *withControls) Health() *filedlp.Health {
	var h *filedlp.Health
	if w.files != nil {
		h = w.files.Health()
	}
	st := w.ctl.Status()
	if st == nil {
		return h
	}
	if h == nil {
		h = &filedlp.Health{State: "running"}
	} else {
		cp := *h
		h = &cp
	}
	h.NetworkControl = st
	return h
}

// TakeUserFile passes a file a session helper handed over to the file hook,
// when it takes them (filedlp.UserFileTaker).
func (w *withControls) TakeUserFile(from ipc.Identity, f ipc.UserFile) {
	if t, ok := w.files.(filedlp.UserFileTaker); ok {
		t.TakeUserFile(from, f)
	}
}
