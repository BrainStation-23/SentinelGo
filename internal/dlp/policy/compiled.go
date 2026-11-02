package policy

import (
	"fmt"
	"slices"
	"sync"

	"sentinelgo/internal/dlp/detect"
)

// ChannelClipboard is the clipboard channel's name in bundles and events.
const ChannelClipboard = "clipboard"

// Compiled is a bundle in the form channels enforce: each clipboard policy's
// rules, and one detection engine over all of them so a copy is scanned once.
type Compiled struct {
	Bundle       *Bundle // what was compiled; the service forwards it to helpers
	Version      string
	EvidenceMode string
	Modules      Modules
	Policies     []CompiledPolicy

	// Clipboard scans clipboard text for every clipboard policy. nil when no
	// policy applies to the clipboard.
	Clipboard *detect.Engine

	// CompileErrors lists the rules (or, with a policy id, the policies) that
	// were skipped. Everything else stays active.
	CompileErrors []detect.CompileError

	// fileRules feed the file engine, built on first use by FilesEngine so
	// session helpers (which only run the clipboard) never pay for it.
	fileRules []detect.Rule
	filesOnce sync.Once
	files     *detect.Engine
	filesErrs []detect.CompileError
}

// FileChunkBytes is how much extracted file text the file engine scans at a
// time (internal/dlp/filescan streams longer text through it in chunks).
const FileChunkBytes = 1 << 20

// CompiledPolicy is one policy ready to evaluate against a scan.
type CompiledPolicy struct {
	Policy
	Rules []detect.Rule
}

// Compile turns b into its enforceable form. A policy with an unknown action
// or match mode is skipped and reported; a rule with an unknown detector or a
// bad custom pattern is skipped and reported while the policy's other rules
// stay active. b must not be nil.
func Compile(b *Bundle) *Compiled {
	c := &Compiled{
		Bundle:       b,
		Version:      b.Version,
		EvidenceMode: b.EvidenceMode,
		Modules:      b.Modules,
	}
	if e := b.Modules.Files.DecodeError; e != "" {
		c.CompileErrors = append(c.CompileErrors, detect.CompileError{RuleID: "modules.files", Error: e})
	}
	var clipboardRules []detect.Rule
	for _, p := range b.Policies {
		if err := validatePolicy(p); err != nil {
			c.CompileErrors = append(c.CompileErrors, detect.CompileError{RuleID: p.ID, Error: err.Error()})
			continue
		}
		cp := CompiledPolicy{Policy: p}
		for _, d := range p.Detectors {
			cp.Rules = append(cp.Rules, detect.Rule{
				DetectorID: d.ID, RuleID: d.RuleID, MinCount: d.MinCount,
				Pattern: d.Pattern, Keywords: d.Keywords, CaseSensitive: d.CaseSensitive,
			})
		}
		if e := p.Exceptions.FileDecodeError; e != "" {
			c.CompileErrors = append(c.CompileErrors, detect.CompileError{RuleID: p.ID, Error: e})
		}
		if e := p.FileFilters.DecodeError; e != "" {
			c.CompileErrors = append(c.CompileErrors, detect.CompileError{RuleID: p.ID, Error: e + " (the policy applies to every file)"})
		}
		c.Policies = append(c.Policies, cp)
		if slices.Contains(p.Channels, ChannelClipboard) {
			clipboardRules = append(clipboardRules, cp.Rules...)
		}
		if slices.ContainsFunc(p.Channels, IsFileChannel) {
			c.fileRules = append(c.fileRules, cp.Rules...)
		}
	}
	if len(clipboardRules) > 0 {
		var errs []detect.CompileError
		c.Clipboard, errs = detect.New(clipboardRules, b.Modules.Clipboard.MaxScanBytes)
		c.CompileErrors = append(c.CompileErrors, errs...)
	}
	return c
}

func validatePolicy(p Policy) error {
	if p.Action != ActionMonitor && p.Action != ActionWarn && p.Action != ActionBlock {
		return fmt.Errorf("policy %q: unknown action %q", p.Name, p.Action)
	}
	if p.Match != "" && p.Match != detect.MatchAny && p.Match != detect.MatchAll {
		return fmt.Errorf("policy %q: unknown match %q", p.Name, p.Match)
	}
	return nil
}

// FilesEngine returns the engine for the file channels' policies, scanning
// FileChunkBytes at a time, and the rules it skipped. It is nil when no policy
// applies to a file channel. Safe for concurrent use.
func (c *Compiled) FilesEngine() (*detect.Engine, []detect.CompileError) {
	c.filesOnce.Do(func() {
		if len(c.fileRules) > 0 {
			c.files, c.filesErrs = detect.New(c.fileRules, FileChunkBytes)
		}
	})
	return c.files, c.filesErrs
}

// ChannelEnabled reports whether the module for channel is switched on. An
// unknown channel is off.
func (c *Compiled) ChannelEnabled(channel string) bool {
	switch {
	case channel == ChannelClipboard:
		return c.Modules.Clipboard.Enabled
	case IsFileChannel(channel):
		return c.Modules.Files.ChannelEnabled(channel)
	default:
		return false
	}
}

// AnyChannelEnabled reports whether at least one channel this agent enforces
// is switched on (file channels aren't enforced yet).
func (c *Compiled) AnyChannelEnabled() bool {
	return c.ChannelEnabled(ChannelClipboard)
}

// For returns the policies that apply to channel.
func (c *Compiled) For(channel string) []CompiledPolicy {
	var out []CompiledPolicy
	for _, p := range c.Policies {
		if slices.Contains(p.Channels, channel) {
			out = append(out, p)
		}
	}
	return out
}
