// Package filedlp is the service side of file DLP (epic #324): it decides
// what a file event means under the policy and records evidence. The OS hook
// that produces events (fanotify on Linux, later a minifilter and an Endpoint
// Security extension) is separate; the Decider doesn't know which one fed it.
//
// This phase is audit-only: files are scanned after they were written to a
// monitored destination, and matches are recorded as "monitored" events.
// Nothing is blocked, whatever a policy's action says (blocking needs the
// permission hooks and fail-safes of #329, and audit data first).
package filedlp

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/detect"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/filescan"
	"sentinelgo/internal/dlp/policy"
)

// Scanner scans an open file (the scan worker pool).
type Scanner interface {
	Scan(ctx context.Context, f *os.File, size int64, timeout time.Duration) filescan.Result
}

// Destination is where a file was written.
type Destination struct {
	Channel     string // policy.ChannelFile*
	Type        string // removable, network_share
	Mount       string // mount point
	VolumeLabel string
	USB         *events.USB
	ShareHost   string
	Source      string // what was mounted (device or //host/share)
}

// Process is the program that wrote the file.
type Process struct {
	PID  int
	Name string
	Exe  string
	UID  string
	User string
}

// Identity is a file's OS identity and version, for the verdict cache.
type Identity struct {
	Dev, Ino   uint64
	Size       int64
	ModTime    int64 // Unix ns
	ChangeTime int64 // Unix ns
}

// Request is one file event: f was written at Path on Dest by Proc.
type Request struct {
	File  *os.File // open for reading; the caller closes it
	Path  string
	Dest  Destination
	Proc  Process
	Ident Identity
	At    time.Time
}

// Stats are the decider's counters.
type Stats struct {
	Scans       uint64 `json:"scans"`
	Cached      uint64 `json:"cached"`
	Events      uint64 `json:"events"`
	Timeouts    uint64 `json:"timeouts"`
	Unscannable uint64 `json:"unscannable"`
}

// cacheSize is how many scan results the decider keeps.
const cacheSize = 4096

// Decider applies the file policies to file events. It is safe for concurrent
// use.
type Decider struct {
	scanner Scanner
	sink    channel.EventSink
	cache   *filescan.Cache

	mu       sync.Mutex
	compiled *policy.Compiled
	engine   *detect.Engine

	scans, cached, emitted, timeouts, unscannable atomic.Uint64
}

// NewDecider returns a Decider that scans with s and records events to sink.
func NewDecider(s Scanner, sink channel.EventSink) *Decider {
	return &Decider{scanner: s, sink: sink, cache: filescan.NewCache(cacheSize)}
}

// Apply switches to c (nil: decide nothing). Cached results of an older
// policy are never reused: the cache key includes the policy version.
func (d *Decider) Apply(c *policy.Compiled) {
	var eng *detect.Engine
	if c != nil {
		eng, _ = c.FilesEngine()
	}
	d.mu.Lock()
	d.compiled, d.engine = c, eng
	d.mu.Unlock()
}

// Invalidate drops cached results for a file (it was written again).
func (d *Decider) Invalidate(id Identity) { d.cache.InvalidateFile(fileID(id)) }

// Stats returns the counters.
func (d *Decider) Stats() Stats {
	return Stats{Scans: d.scans.Load(), Cached: d.cached.Load(), Events: d.emitted.Load(),
		Timeouts: d.timeouts.Load(), Unscannable: d.unscannable.Load()}
}

func fileID(id Identity) string {
	return strconv.FormatUint(id.Dev, 10) + ":" + strconv.FormatUint(id.Ino, 10)
}

// Handle decides one file event and records any evidence.
func (d *Decider) Handle(ctx context.Context, r Request) {
	d.mu.Lock()
	c, eng := d.compiled, d.engine
	d.mu.Unlock()
	if c == nil || !c.ChannelEnabled(r.Dest.Channel) || r.Ident.Size <= 0 {
		return
	}
	pols := applicable(c, r)
	if len(pols) == 0 {
		return // nothing to decide: don't read the file
	}

	key := filescan.CacheKey{FileID: fileID(r.Ident), Size: r.Ident.Size, ModTime: r.Ident.ModTime,
		ChangeTime: r.Ident.ChangeTime, PolicyVersion: c.Version}
	source := "cache"
	res, ok := d.cache.Get(key)
	if ok {
		d.cached.Add(1)
	} else {
		source = "scan"
		timeout := time.Duration(c.Modules.Files.ScanTimeoutMs) * time.Millisecond
		res = d.scanner.Scan(ctx, r.File, r.Ident.Size, timeout)
		d.scans.Add(1)
		d.cache.Put(key, res)
	}
	switch {
	case res.Status == filescan.StatusTimeout:
		d.timeouts.Add(1)
	case filescan.IsUnscannable(res.Status):
		d.unscannable.Add(1)
	}

	files := c.Modules.Files
	for _, p := range pols {
		matched, findings := evaluate(eng, p, res)
		switch {
		case matched:
		case filescan.IsUnscannable(res.Status) && files.OnUnscannable != policy.OnFailAllow:
		case res.Status == filescan.StatusTimeout && files.OnTimeout == policy.OnFailBlock:
		default:
			continue
		}
		d.sink.Emit(buildEvent(c, p, r, res, findings, source))
		d.emitted.Add(1)
	}
}

// applicable returns the policies for r's channel that no exception rules out.
func applicable(c *policy.Compiled, r Request) []policy.CompiledPolicy {
	var out []policy.CompiledPolicy
	for _, p := range c.For(r.Dest.Channel) {
		if !excepted(p.Exceptions, r) {
			out = append(out, p)
		}
	}
	return out
}

// excepted reports whether a policy's exceptions cover r: the writing app (by
// path, or name as the bundle gives it), the device, or the share.
func excepted(ex policy.Exceptions, r Request) bool {
	for _, a := range ex.Apps {
		if a.Path != "" && a.Path == r.Proc.Exe || a.Name != "" && strings.EqualFold(a.Name, r.Proc.Name) {
			return true
		}
	}
	for _, name := range ex.SourceApps {
		if name != "" && (name == r.Proc.Exe || strings.EqualFold(name, r.Proc.Name)) {
			return true
		}
	}
	if TrustedDevice(ex.TrustedDevices, r.Dest.USB) || TrustedShare(ex.TrustedShares, r.Dest) {
		return true
	}
	return false
}

// TrustedDevice reports whether usb matches one of the trusted devices
// (vendor and product, and the serial when the entry has one).
func TrustedDevice(trusted []policy.Device, usb *events.USB) bool {
	if usb == nil {
		return false
	}
	for _, t := range trusted {
		if t.VendorID == "" || !strings.EqualFold(t.VendorID, usb.VendorID) || !strings.EqualFold(t.ProductID, usb.ProductID) {
			continue
		}
		if t.Serial == "" || t.Serial == usb.Serial {
			return true
		}
	}
	return false
}

// TrustedShare reports whether dest is one of the trusted shares, given as a
// host or as the mounted source (//host/share, host:/path).
func TrustedShare(trusted []string, dest Destination) bool {
	if dest.Type != TypeNetworkShare {
		return false
	}
	for _, t := range trusted {
		t = strings.TrimSpace(strings.ReplaceAll(t, `\`, "/"))
		if t == "" {
			continue
		}
		if strings.EqualFold(t, dest.ShareHost) || strings.EqualFold(strings.TrimRight(t, "/"), strings.TrimRight(dest.Source, "/")) {
			return true
		}
	}
	return false
}

// evaluate checks a policy against a result: the file's own text, or any one
// archive entry (an archive matches when one of its files does).
func evaluate(eng *detect.Engine, p policy.CompiledPolicy, res filescan.Result) (bool, []detect.Finding) {
	if eng == nil {
		return false, nil
	}
	var used []detect.Finding
	matched := false
	if ok, f := eng.Evaluate(p.Match, p.Rules, detect.Result{Findings: res.Findings}); ok {
		matched, used = true, append(used, f...)
	}
	for _, e := range res.Entries {
		if ok, f := eng.Evaluate(p.Match, p.Rules, detect.Result{Findings: e.Findings}); ok {
			matched, used = true, append(used, f...)
		}
	}
	return matched, used
}

// buildEvent records a file event. Audit-only: the action is always
// "monitored".
func buildEvent(c *policy.Compiled, p policy.CompiledPolicy, r Request, res filescan.Result,
	findings []detect.Finding, source string) events.Event {
	ev := events.Event{
		EventID:       events.NewID(),
		OccurredAt:    r.At.UTC(),
		Channel:       r.Dest.Channel,
		PolicyID:      p.ID,
		PolicyVersion: c.Version,
		Action:        events.ActionMonitored,
		Severity:      p.Severity,
		User:          r.Proc.User,
		SessionID:     r.Proc.UID,
		Findings:      []events.Finding{},
		ContentLength: int(min(r.Ident.Size, int64(^uint32(0)>>1))),
		ContentSHA256: res.SHA256,
		Truncated:     res.Status == filescan.StatusTruncated,
		RepeatCount:   1,
		File: &events.File{
			Name:         events.FileName(c.EvidenceMode, r.Path),
			Ext:          strings.TrimPrefix(strings.ToLower(filepath.Ext(r.Path)), "."),
			DetectedType: res.DetectedType,
			Size:         r.Ident.Size,
			SHA256:       res.SHA256,
		},
		Destination: &events.Destination{Type: r.Dest.Type, VolumeLabel: r.Dest.VolumeLabel, USB: r.Dest.USB, ShareHost: r.Dest.ShareHost},
		Process:     &events.Process{Name: r.Proc.Name, Path: r.Proc.Exe},
		Scan:        &events.Scan{Status: res.Status, VerdictSource: source, DurationMs: res.Duration.Milliseconds()},
	}
	for _, f := range findings {
		fd := events.Finding{Detector: f.DetectorID, Count: f.Count, Masked: f.Masked, SHA256: f.SHA256}
		if c.EvidenceMode == policy.EvidenceNone {
			fd.Masked = ""
		}
		ev.Findings = append(ev.Findings, fd)
	}
	return ev
}

// Destination types.
const (
	TypeRemovable    = "removable"
	TypeNetworkShare = "network_share"
)
