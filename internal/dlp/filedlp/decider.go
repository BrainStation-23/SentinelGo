// Package filedlp is the service side of file DLP (epic #324): it decides
// what a file event means under the policy and records evidence. The OS hook
// that produces events (fanotify on Linux, later a minifilter and an Endpoint
// Security extension) is separate; the Decider doesn't know which one fed it.
//
// Files are scanned after they were written to a monitored destination
// (Handle), and matches are recorded as events; on_close_violation decides
// what happens to the written file. Where a permission hook can hold the
// creation of a file (Linux, #333), DecideBySources judges it before
// anything is written, by the files its writer has open, and can refuse it.
package filedlp

import (
	"context"
	"log"
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
	Host        string // uploads: the destination host, never the URL
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
	// NoCache skips the verdict cache: for inputs whose identity is reused
	// (an upload's spill file is deleted after the scan, its inode recycled).
	NoCache bool
	// Sources are the files the writing process read just before, newest
	// first (process taint); empty when taint is off.
	Sources []SourceRef
}

// Stats are the decider's counters.
type Stats struct {
	Scans       uint64 `json:"scans"`
	Cached      uint64 `json:"cached"`
	Events      uint64 `json:"events"`
	Timeouts    uint64 `json:"timeouts"`
	Unscannable uint64 `json:"unscannable"`
	Correlated  uint64 `json:"correlated"` // verdicts taken from a source file (process taint)
}

// cacheSize is how many scan results the decider keeps.
const cacheSize = 4096

// Decider applies the file policies to file events. It is safe for concurrent
// use.
type Decider struct {
	scanner Scanner
	sink    channel.EventSink
	cache   *filescan.Cache

	mu         sync.Mutex
	compiled   *policy.Compiled
	engine     *detect.Engine
	remediate  func(r Request, action string) error
	openSource func(SourceRef) (*os.File, Identity, error)
	notices    *notices
	overrides  *overrides
	asking     asking

	requestException func(context.Context, ExceptionRequest) error

	scans, cached, emitted, timeouts, unscannable, correlated atomic.Uint64
}

// NewDecider returns a Decider that scans with s and records events to sink.
func NewDecider(s Scanner, sink channel.EventSink) *Decider {
	return &Decider{scanner: s, sink: sink, cache: filescan.NewCache(cacheSize), overrides: newOverrides()}
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

// SetRemediator gives the decider what quarantines or deletes a file found
// to violate a policy after it was written (on_close_violation). action is
// policy.ViolationQuarantine or policy.ViolationDelete. Without one, such
// files are only recorded.
func (d *Decider) SetRemediator(fn func(r Request, action string) error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.remediate = fn
}

// SetSourceOpener gives the decider what reopens a file a process read
// (process taint): it must open src read-only, check it is still the same
// file and return its identity.
func (d *Decider) SetSourceOpener(fn func(src SourceRef) (*os.File, Identity, error)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.openSource = fn
}

// SetUserNotifier makes blocks, removals and warnings tell the user whose
// process caused them (#336); nil tells nobody.
func (d *Decider) SetUserNotifier(n UserNotifier) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if n == nil {
		d.notices = nil
		return
	}
	d.notices = newNotices(n)
}

// tell queues a notice for an event's user and records whether they could be
// told.
func (d *Decider) tell(ev *events.Event, r Request, kind string, v Verdict, findings []detect.Finding) {
	d.mu.Lock()
	n := d.notices
	d.mu.Unlock()
	sha := ""
	if ev.File != nil {
		sha = ev.File.SHA256
	}
	told := n.report(r, kind, sha, findings, v)
	ev.UserNotified = &told
}

// Files returns the files module of the policy in force (zero when none).
func (d *Decider) Files() policy.FilesModule {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.compiled == nil {
		return policy.FilesModule{}
	}
	return d.compiled.Modules.Files
}

// Invalidate drops cached results for a file (it was written again).
func (d *Decider) Invalidate(id Identity) { d.cache.InvalidateFile(fileID(id)) }

// Stats returns the counters.
func (d *Decider) Stats() Stats {
	return Stats{Scans: d.scans.Load(), Cached: d.cached.Load(), Events: d.emitted.Load(),
		Timeouts: d.timeouts.Load(), Unscannable: d.unscannable.Load(), Correlated: d.correlated.Load()}
}

func fileID(id Identity) string {
	return strconv.FormatUint(id.Dev, 10) + ":" + strconv.FormatUint(id.Ino, 10)
}

// Verdict is what a hook that can hold the operation should do.
type Verdict struct {
	Block   bool
	Message string // the files module's block message, for the user
	// Overridable is set when the block came from a block_override policy:
	// its user may go ahead with a reason (EventID names the block).
	Overridable bool
	EventID     string
}

// released reports whether a block by p is lifted for this file and user:
// an approved exception (modules.files.exceptions), or, for block_override,
// an override the user made a moment ago.
func (d *Decider) released(c *policy.Compiled, p policy.CompiledPolicy, r Request, sha string) bool {
	now := time.Now()
	for _, e := range c.Modules.Files.Exceptions {
		if e.Allows(p.ID, r.Dest.Channel, sha, r.Proc.User, now) {
			return true
		}
	}
	return p.Action == policy.ActionBlockOverride && d.overrides.allowed(r.Proc.UID, r.Dest.Channel, sha)
}

// blocked records a block's verdict, and keeps a block_override block so its
// user can override it.
func (d *Decider) blocked(c *policy.Compiled, p policy.CompiledPolicy, ev events.Event, r Request, sha string, findings []detect.Finding) Verdict {
	v := Verdict{Block: true, Message: blockMessage(c.Modules.Files.BlockMessage, findings), EventID: ev.EventID}
	if p.Action == policy.ActionBlockOverride && r.Proc.UID != "" && sha != "" {
		if limit := c.Modules.Files.DailyOverrides(); limit > 0 {
			v.Overridable = true
			d.overrides.remember(ev, r.Proc.UID, sha, limit)
		}
	}
	return v
}

// Override lets the file of a block_override block through for its user,
// with their reason, and records an "overridden" event. uid must be the
// blocked process's user: only their own session helper can ask. The reason
// is never logged.
func (d *Decider) Override(eventID, uid, reason string) error {
	ev, err := d.overrides.override(eventID, uid, reason)
	if err != nil {
		return err
	}
	d.sink.Emit(ev)
	d.emitted.Add(1)
	return nil
}

// Blocked returns a block_override block still open for its user (for an
// exception request): the event, and the blocked file's hash.
func (d *Decider) Blocked(eventID, uid string) (events.Event, string, bool) {
	p, ok := d.overrides.pendingFor(eventID, uid)
	return p.ev, p.sha, ok
}

// Handle decides one file event and records any evidence, for hooks that
// can't block (the Linux monitor sees files after they were written).
func (d *Decider) Handle(ctx context.Context, r Request) { d.Decide(ctx, r, false) }

// Decide decides one file event, records any evidence and returns the
// verdict. It blocks only when canBlock is true, the files module isn't
// audit-only, and a matching policy's action is block, or the file couldn't
// be scanned and on_unscannable / on_timeout say block. Events record what
// was done: blocked, or monitored.
func (d *Decider) Decide(ctx context.Context, r Request, canBlock bool) Verdict {
	d.mu.Lock()
	c, eng, remediate := d.compiled, d.engine, d.remediate
	d.mu.Unlock()
	if c == nil || !c.ChannelEnabled(r.Dest.Channel) || r.Ident.Size <= 0 {
		return Verdict{}
	}
	pols := applicable(c, r)
	if len(pols) == 0 {
		return Verdict{} // nothing to decide: don't read the file
	}

	key := filescan.CacheKey{FileID: fileID(r.Ident), Size: r.Ident.Size, ModTime: r.Ident.ModTime,
		ChangeTime: r.Ident.ChangeTime, PolicyVersion: c.Version}
	source := "cache"
	res, ok := filescan.Result{}, false
	if !r.NoCache {
		res, ok = d.cache.Get(key)
	}
	if ok {
		d.cached.Add(1)
	} else {
		source = "scan"
		timeout := time.Duration(c.Modules.Files.ScanTimeoutMs) * time.Millisecond
		res = d.scanner.Scan(ctx, r.File, r.Ident.Size, timeout)
		d.scans.Add(1)
		if !r.NoCache {
			d.cache.Put(key, res)
		}
	}
	switch {
	case res.Status == filescan.StatusTimeout:
		d.timeouts.Add(1)
	case filescan.IsUnscannable(res.Status):
		d.unscannable.Add(1)
	}

	files := c.Modules.Files
	mayBlock := canBlock && !files.IsAuditOnly()
	ext := fileExt(r.Path)
	after := afterWrite{r: r, files: files, remediate: remediate}

	// Outcomes for the written file itself.
	var outs []outcome
	anyMatch := false
	for _, p := range pols {
		matched, findings := evaluate(eng, p, res, ext)
		typeOK := p.FileFilters.TypeOK(ext, res.DetectedType)
		o := outcome{p: p, findings: findings}
		switch {
		case matched:
			o.block = p.Blocks() && !d.released(c, p, r, res.SHA256)
			anyMatch = true
		case !typeOK:
			continue // not a file type this policy covers
		case filescan.IsUnscannable(res.Status) && files.OnUnscannable != policy.OnFailAllow:
			o.block = files.OnUnscannable == policy.OnFailBlock
		case res.Status == filescan.StatusTimeout && files.OnTimeout == policy.OnFailBlock:
			o.block = true
		default:
			continue
		}
		outs = append(outs, o)
	}

	// Process taint: a written file that couldn't be judged on its own
	// (unreadable, or an archive) is judged by what its writer read just
	// before. Only after the write: a hook that holds the operation has the
	// file itself.
	var corr *events.Correlation
	if !anyMatch && !canBlock && files.CopyCorrelation.ProcessTaint && needsCorrelation(res) && len(r.Sources) > 0 {
		if cOuts, cRef, _ := d.correlate(ctx, c, eng, pols, r, "taint"); len(cOuts) > 0 {
			outs, corr, source = cOuts, cRef, "correlation"
		}
	}

	var v Verdict
	for _, o := range outs {
		ev := buildEvent(c, o.p, r, res, o.findings, source)
		ev.Correlation = corr
		var openDialog func()
		switch {
		case o.block && mayBlock:
			ev.Action = events.ActionBlocked
			v = d.blocked(c, o.p, ev, r, res.SHA256, o.findings)
			openDialog = d.tellBlock(&ev, r, v, res.SHA256, files.DailyOverrides(), o.findings)
		case o.block && canBlock:
			ev.WouldHave = events.ActionBlocked // audit-only
		case o.block:
			ev.Action, ev.WouldHave = after.handle()
			if ev.Action == events.ActionQuarantined || ev.Action == events.ActionDeleted {
				d.tell(&ev, r, noticeRemoved, Verdict{}, o.findings)
			}
		case o.p.Action == policy.ActionWarn && len(o.findings) > 0:
			d.tell(&ev, r, noticeWarned, Verdict{}, o.findings)
		}
		d.sink.Emit(ev)
		d.emitted.Add(1)
		if openDialog != nil {
			openDialog() // after the block event, so an override follows it
		}
	}
	return v
}

// outcome is what one policy says about a file.
type outcome struct {
	p        policy.CompiledPolicy
	findings []detect.Finding
	block    bool
}

// needsCorrelation reports whether a written file can't be judged on its
// own: it couldn't be read, or it's an archive (which a process may have
// built from sensitive files, e.g. encrypted on the fly). A readable file
// that matched nothing is clean as written, so its writer's earlier reads
// are not held against it.
func needsCorrelation(res filescan.Result) bool {
	return filescan.IsUnscannable(res.Status) || res.Status == filescan.StatusTimeout ||
		strings.HasPrefix(res.DetectedType, "archive.")
}

// correlate checks the files r's writer read before the write, newest first,
// and returns the policies the first matching one violates, with the link
// to it. Sources are reopened (and checked to be the same file) by the
// source opener and scanned like any file, through the cache.
func (d *Decider) correlate(ctx context.Context, c *policy.Compiled, eng *detect.Engine, pols []policy.CompiledPolicy, r Request, method string) ([]outcome, *events.Correlation, filescan.Result) {
	d.mu.Lock()
	open := d.openSource
	d.mu.Unlock()
	if open == nil {
		return nil, nil, filescan.Result{}
	}
	timeout := time.Duration(c.Modules.Files.ScanTimeoutMs) * time.Millisecond
	for _, src := range r.Sources {
		f, ident, err := open(src)
		if err != nil {
			continue
		}
		key := filescan.CacheKey{FileID: fileID(ident), Size: ident.Size, ModTime: ident.ModTime, ChangeTime: ident.ChangeTime, PolicyVersion: c.Version}
		res, ok := d.cache.Get(key)
		if !ok {
			res = d.scanner.Scan(ctx, f, ident.Size, timeout)
			d.scans.Add(1)
			d.cache.Put(key, res)
		}
		_ = f.Close()
		ext := fileExt(src.Path)
		var outs []outcome
		for _, p := range pols {
			if !p.FileFilters.SizeOK(ident.Size) {
				continue
			}
			if matched, findings := evaluate(eng, p, res, ext); matched {
				outs = append(outs, outcome{p: p, findings: findings, block: p.Blocks() && !d.released(c, p, r, res.SHA256)})
			}
		}
		if len(outs) > 0 {
			d.correlated.Add(1)
			return outs, &events.Correlation{Method: method, SourceSHA256: res.SHA256, SourceName: events.FileName(c.EvidenceMode, src.Path)}, res
		}
	}
	return nil, nil, filescan.Result{}
}

// Correlation methods for DecideBySources.
const (
	MethodOpenFile = "open_file" // a file the writer has open while it creates the destination file
)

// DecideBySources decides a file being created at a destination before
// anything is written to it (a permission hook that holds the open), by the
// files its writer has open or read just before (r.Sources, newest first).
// It blocks only when the files module isn't audit-only and a source matches
// a block policy. Only a block is recorded: an allowed copy is recorded by
// the after-write path when the file is closed, so it isn't counted twice.
func (d *Decider) DecideBySources(ctx context.Context, r Request, method string) Verdict {
	d.mu.Lock()
	c, eng := d.compiled, d.engine
	d.mu.Unlock()
	if c == nil || !c.ChannelEnabled(r.Dest.Channel) || len(r.Sources) == 0 || c.Modules.Files.IsAuditOnly() {
		return Verdict{}
	}
	var pols []policy.CompiledPolicy
	for _, p := range c.For(r.Dest.Channel) {
		if p.Blocks() && !excepted(p.Exceptions, r) {
			pols = append(pols, p)
		}
	}
	if len(pols) == 0 {
		return Verdict{}
	}
	outs, corr, res := d.correlate(ctx, c, eng, pols, r, method)
	var v Verdict
	for _, o := range outs {
		if !o.block {
			continue
		}
		ev := buildEvent(c, o.p, r, res, o.findings, "correlation")
		ev.Correlation = corr
		ev.Action = events.ActionBlocked
		v = d.blocked(c, o.p, ev, r, res.SHA256, o.findings)
		openDialog := d.tellBlock(&ev, r, v, res.SHA256, c.Modules.Files.DailyOverrides(), o.findings)
		d.sink.Emit(ev)
		d.emitted.Add(1)
		if openDialog != nil {
			openDialog() // after the block event, so an override follows it
		}
	}
	return v
}

// afterWrite applies on_close_violation to a file found to violate a policy
// after it was written (a hook that can't block). It acts once per file,
// however many policies it violates.
type afterWrite struct {
	r         Request
	files     policy.FilesModule
	remediate func(Request, string) error

	done              bool
	action, wouldHave string
}

// handle returns the event's action and would_have.
func (a *afterWrite) handle() (string, string) {
	if a.done {
		return a.action, a.wouldHave
	}
	a.done = true
	a.action = events.ActionMonitored
	mode := a.files.CopyCorrelation.OnCloseViolation
	var did string
	switch mode {
	case policy.ViolationQuarantine:
		did = events.ActionQuarantined
	case policy.ViolationDelete:
		did = events.ActionDeleted
	default:
		return a.action, "" // record
	}
	switch {
	case a.files.IsAuditOnly():
		a.wouldHave = did
	case a.remediate == nil:
	default:
		if err := a.remediate(a.r, mode); err != nil {
			log.Printf("DLP: could not %s a file that violates a policy: %v", mode, err)
		} else {
			a.action = did
		}
	}
	return a.action, a.wouldHave
}

// defaultFileBlockMessage is used when the bundle has none.
const defaultFileBlockMessage = "SentinelOps blocked this file: {{detector}}"

// blockMessage fills {{detector}} with the detectors that matched (never the
// matched values).
func blockMessage(tmpl string, findings []detect.Finding) string {
	if tmpl == "" {
		tmpl = defaultFileBlockMessage
	}
	var ids []string
	seen := map[string]bool{}
	for _, f := range findings {
		if !seen[f.DetectorID] {
			seen[f.DetectorID] = true
			ids = append(ids, f.DetectorID)
		}
	}
	what := strings.Join(ids, ", ")
	if what == "" {
		what = "a file that couldn't be checked"
	}
	return strings.ReplaceAll(tmpl, "{{detector}}", what)
}

// applicable returns the policies for r's channel that no exception or size
// filter rules out (type filters need the scan, see evaluate).
func applicable(c *policy.Compiled, r Request) []policy.CompiledPolicy {
	var out []policy.CompiledPolicy
	for _, p := range c.For(r.Dest.Channel) {
		if !excepted(p.Exceptions, r) && p.FileFilters.SizeOK(r.Ident.Size) {
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
// archive entry (an archive matches when one of its files does). A policy's
// type filter applies to the file and to each entry on its own, so a policy
// for xlsx files still catches a spreadsheet inside a zip.
func evaluate(eng *detect.Engine, p policy.CompiledPolicy, res filescan.Result, ext string) (bool, []detect.Finding) {
	if eng == nil {
		return false, nil
	}
	var used []detect.Finding
	matched := false
	if p.FileFilters.TypeOK(ext, res.DetectedType) {
		if ok, f := eng.Evaluate(p.Match, p.Rules, detect.Result{Findings: res.Findings}); ok {
			matched, used = true, append(used, f...)
		}
	}
	for _, e := range res.Entries {
		if !p.FileFilters.TypeOK(fileExt(e.Name), e.DetectedType) {
			continue
		}
		if ok, f := eng.Evaluate(p.Match, p.Rules, detect.Result{Findings: e.Findings}); ok {
			matched, used = true, append(used, f...)
		}
	}
	return matched, used
}

// fileExt is a path's extension, lowercase and without the dot.
func fileExt(path string) string {
	return strings.TrimPrefix(strings.ToLower(filepath.Ext(path)), ".")
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
			Ext:          fileExt(r.Path),
			DetectedType: res.DetectedType,
			Size:         r.Ident.Size,
			SHA256:       res.SHA256,
		},
		Destination: &events.Destination{Type: r.Dest.Type, VolumeLabel: r.Dest.VolumeLabel, USB: r.Dest.USB, ShareHost: r.Dest.ShareHost, Host: r.Dest.Host},
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
	TypeUpload       = "upload"
	TypeCloudSync    = "cloud_sync"
)
