package uploadproxy

// WithUploads puts the upload Service next to the platform's file DLP hook,
// as the one filedlp.Enforcer the DLP Manager drives: file.upload's
// capability comes from the Service, and its status goes in the files
// health as deep_inspection.

import (
	"context"
	"sync"

	"sentinelgo/internal/dlp/filedlp"
	"sentinelgo/internal/dlp/policy"
)

type withUploads struct {
	files filedlp.Enforcer // nil where file DLP has no hook
	svc   *Service

	mu       sync.Mutex
	compiled *policy.Compiled
}

// WithUploads returns an Enforcer that runs files (may be nil) and svc.
func WithUploads(files filedlp.Enforcer, svc *Service) filedlp.Enforcer {
	return &withUploads{files: files, svc: svc}
}

func (w *withUploads) Wants(m policy.FilesModule) bool {
	return w.svc.Wants(m) || w.files != nil && w.files.Wants(m)
}

func (w *withUploads) Apply(ctx context.Context, c *policy.Compiled) {
	w.mu.Lock()
	w.compiled = c
	w.mu.Unlock()
	if w.files != nil {
		w.files.Apply(ctx, c)
	}
	w.svc.Apply(ctx, c)
}

func (w *withUploads) Stop() {
	w.mu.Lock()
	w.compiled = nil
	w.mu.Unlock()
	if w.files != nil {
		w.files.Stop()
	}
	w.svc.Stop()
}

func (w *withUploads) Capabilities() map[string]string {
	var caps map[string]string
	if w.files != nil {
		caps = w.files.Capabilities()
	}
	w.mu.Lock()
	c := w.compiled
	w.mu.Unlock()
	if c == nil || !c.Modules.Files.Enabled || !c.Modules.Files.ChannelEnabled(policy.ChannelFileUpload) {
		return caps
	}
	if caps == nil {
		caps = map[string]string{}
	}
	if c.Modules.Files.InspectsUploads() {
		caps[policy.ChannelFileUpload] = w.svc.Capability()
	} else {
		caps[policy.ChannelFileUpload] = "unsupported:inspection_off"
	}
	return caps
}

func (w *withUploads) CopyCorrelation() map[string]string {
	if w.files == nil {
		return nil
	}
	return w.files.CopyCorrelation()
}

func (w *withUploads) Health() *filedlp.Health {
	var h *filedlp.Health
	if w.files != nil {
		h = w.files.Health()
	}
	st := w.svc.Status()
	if st == nil {
		return h
	}
	if h == nil {
		h = &filedlp.Health{State: "running"}
	} else {
		cp := *h
		h = &cp
	}
	h.DeepInspection = st
	return h
}
