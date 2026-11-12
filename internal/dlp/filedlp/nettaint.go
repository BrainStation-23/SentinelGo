package filedlp

// Taint blocks (#427, Compliance-OS#910): when an egress app (a browser, a
// chat client: modules.files.egress_apps) opens a file that a file.upload
// policy would block, the app's new connections are cut for a few minutes
// (netctl, WFP), so it can't upload what it just read. Only Windows has the
// open events (ETW) and the firewall for it; the decision is OS-neutral.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/filescan"
	"sentinelgo/internal/dlp/policy"
)

// TypeNetwork is a taint block's destination type.
const TypeNetwork = "network"

// NetworkTainter cuts an app's new connections until a time (netctl).
type NetworkTainter interface {
	TaintBlock(exe string, until time.Time)
}

// DecideNetworkTaint decides a file an egress app opened: r.File is the
// file, r.Proc the app. When a file.upload policy that blocks matches it,
// it records one event (blocked, or monitored with would_have
// network_blocked in audit-only) and returns when the block ends, and
// whether to block (never in audit-only).
func (d *Decider) DecideNetworkTaint(ctx context.Context, r Request) (time.Time, bool) {
	d.mu.Lock()
	c, eng := d.compiled, d.engine
	d.mu.Unlock()
	r.Dest = Destination{Channel: policy.ChannelFileUpload, Type: TypeNetwork}
	if c == nil || !c.ChannelEnabled(policy.ChannelFileUpload) || r.Ident.Size <= 0 {
		return time.Time{}, false
	}
	var pols []policy.CompiledPolicy
	for _, p := range c.For(policy.ChannelFileUpload) {
		if p.Blocks() && !excepted(p.Exceptions, r) && p.FileFilters.SizeOK(r.Ident.Size) {
			pols = append(pols, p)
		}
	}
	if len(pols) == 0 {
		return time.Time{}, false // nothing could taint: don't read the file
	}
	key := filescan.CacheKey{FileID: fileID(r.Ident), Size: r.Ident.Size, ModTime: r.Ident.ModTime,
		ChangeTime: r.Ident.ChangeTime, PolicyVersion: c.Version}
	source := "cache"
	res, ok := d.cache.Get(key)
	if ok {
		d.cached.Add(1)
	} else {
		source = "scan"
		res = d.scanner.Scan(ctx, r.File, r.Ident.Size, time.Duration(c.Modules.Files.ScanTimeoutMs)*time.Millisecond)
		d.scans.Add(1)
		d.cache.Put(key, res)
	}
	ext := fileExt(r.Path)
	for _, p := range pols {
		matched, findings := evaluate(eng, p, res, ext)
		if !matched || d.released(c, p, r, res.SHA256) {
			continue
		}
		minutes := c.Modules.Files.NetworkControl.TaintBlock.Minutes
		until := r.At.Add(time.Duration(minutes) * time.Minute)
		ev := buildEvent(c, p, r, res, findings, source)
		ev.Correlation = &events.Correlation{Method: "taint", SourceSHA256: res.SHA256, SourceName: events.FileName(c.EvidenceMode, r.Path)}
		ev.NetworkBlock = &events.NetworkBlock{Until: until.UTC(), Minutes: minutes}
		block := !c.Modules.Files.IsAuditOnly()
		if block {
			ev.Action = events.ActionBlocked
			msg := fmt.Sprintf("Its new connections are blocked for %d minutes, except to company destinations. Ask IT if you need to share this.", minutes)
			d.tell(&ev, r, noticeNetworkBlocked, Verdict{Message: msg}, findings)
		} else {
			ev.WouldHave = events.NetworkBlocked
		}
		d.sink.Emit(ev)
		d.emitted.Add(1)
		return until, block
	}
	return time.Time{}, false
}

// CapTaintBlock is the taint block's capability name (netctl reports it;
// the file hook says why it can't when the ETW trace failed).
const CapTaintBlock = "network_control.taint_block"

// Egress open handling: tuning; vars for tests.
var (
	egressQueueSize = 256
	egressRecheck   = 10 * time.Minute // the same app and file aren't judged again before this
	egressProcTTL   = time.Minute      // how long a pid's executable is remembered
	maxEgressSeen   = 4096
)

// egressOpen is one open by some process of a file under the user
// profiles, from the ETW trace.
type egressOpen struct {
	pid  uint32
	path string
	at   time.Time
}

type egressProc struct {
	p    Process
	seen time.Time
}

// egressTaints judges the files egress apps open and starts taint blocks.
// The trace hands opens over without waiting (offer); one goroutine (run)
// does the rest.
type egressTaints struct {
	d       *Decider
	tainter NetworkTainter
	// Seams: the process behind a pid, reopening a file, the environment
	// for %VAR% in egress_apps paths, and the policy in force.
	procInfo func(pid uint32) Process
	open     func(SourceRef) (*os.File, Identity, error)
	env      map[string]string
	compiled func() *policy.Compiled
	goos     string

	queue   chan egressOpen
	dropped atomic.Uint64

	procs   map[uint32]egressProc
	seen    map[string]time.Time // exe|path → last judged
	blocked map[string]time.Time // exe → until
}

func newEgressTaints(d *Decider, t NetworkTainter, goos string, compiled func() *policy.Compiled) *egressTaints {
	return &egressTaints{d: d, tainter: t, goos: goos, compiled: compiled, queue: make(chan egressOpen, egressQueueSize),
		procs: map[uint32]egressProc{}, seen: map[string]time.Time{}, blocked: map[string]time.Time{}}
}

// offer queues an open without blocking the caller (the trace's thread);
// a full queue drops it and counts it.
func (g *egressTaints) offer(o egressOpen) {
	select {
	case g.queue <- o:
	default:
		g.dropped.Add(1)
	}
}

// run handles opens until ctx ends.
func (g *egressTaints) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case o := <-g.queue:
			g.handle(ctx, o)
		}
	}
}

// handle judges one open: only by an egress app, only a file it hasn't been
// judged for lately, and not while that app is already cut off.
func (g *egressTaints) handle(ctx context.Context, o egressOpen) {
	c := g.compiled()
	if c == nil || !c.Modules.Files.TaintsNetwork(g.goos) {
		return
	}
	p := g.process(o.pid, o.at)
	if p.Exe == "" || !g.isEgress(c.Modules.Files.EgressApps[g.goos], p.Exe) {
		return
	}
	exe := strings.ToLower(p.Exe)
	if until, ok := g.blocked[exe]; ok && o.at.Before(until) {
		return
	}
	key := exe + "|" + strings.ToLower(o.path)
	if last, ok := g.seen[key]; ok && o.at.Sub(last) < egressRecheck {
		return
	}
	g.remember(key, o.at)
	f, ident, err := g.open(SourceRef{Path: o.path})
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	if ident.Size <= 0 || ident.Size > c.Modules.Files.MaxFileBytes {
		return
	}
	until, block := g.d.DecideNetworkTaint(ctx, Request{File: f, Path: o.path, Proc: p, Ident: ident, At: o.at})
	if !block {
		return
	}
	g.blocked[exe] = until
	g.tainter.TaintBlock(p.Exe, until)
}

func (g *egressTaints) process(pid uint32, now time.Time) Process {
	if e, ok := g.procs[pid]; ok && now.Sub(e.seen) < egressProcTTL {
		return e.p
	}
	p := g.procInfo(pid)
	if len(g.procs) >= maxEgressSeen {
		clear(g.procs)
	}
	g.procs[pid] = egressProc{p: p, seen: now}
	return p
}

func (g *egressTaints) isEgress(apps []policy.App, exe string) bool {
	for _, a := range apps {
		if a.MatchesExe(exe, g.env) {
			return true
		}
	}
	return false
}

func (g *egressTaints) remember(key string, now time.Time) {
	if len(g.seen) >= maxEgressSeen {
		for k, t := range g.seen {
			if now.Sub(t) >= egressRecheck {
				delete(g.seen, k)
			}
		}
		if len(g.seen) >= maxEgressSeen {
			clear(g.seen)
		}
	}
	g.seen[key] = now
	for k, until := range g.blocked {
		if !now.Before(until) {
			delete(g.blocked, k)
		}
	}
}

// userFile reports whether a path under the profiles folder is a file a
// user would pick to upload: not in AppData, where browsers and chat
// clients open thousands of their own files.
func userFile(lowerPath string) bool {
	return !strings.Contains(lowerPath, `\appdata\`)
}
