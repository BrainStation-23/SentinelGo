//go:build linux || windows || darwin

package scanworker

// YARA scans in the sandboxed workers (#412). The worker compiles the rule
// sources itself, so a compiler bug, like a matcher bug, costs a worker and
// never the service. The service keeps a separate Pool for YARA (one worker
// by default), so a long full scan never starves file DLP's blocking
// decisions.
//
// Per scan, the worker reads the file once to hash it, running the first
// ruleset in the same pass, and once more for each further ruleset (through
// ReadAt, so the passes don't share a file offset). Results carry rule and
// string identifiers only.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"

	"sentinelgo/internal/yara"
	"sentinelgo/internal/yara/engine"
)

// YARA scan statuses (YARAResult.Status).
const (
	YARAScanned        = "scanned"
	YARATimeout        = "timeout"          // the per-file timeout: the file is skipped, the scan goes on
	YARAWorkerFailed   = ReasonWorkerFailed // no worker could scan it (crash, kill, pool disabled)
	YARAReadError      = "read_error"       // the file couldn't be read to the end
	YARANoRules        = "no_rules"         // the worker has no compiled ruleset to scan with
	DefaultYARATimeout = 10 * time.Second   // contract default per_file_timeout_ms
	// MaxYARAMatches caps the rules one file reports; more is noise from a
	// bad rule.
	MaxYARAMatches = 100
)

// YARAResult is one file's YARA outcome. SHA256 and Size come from the same
// read as the matching (#415: no second read by the service).
type YARAResult struct {
	Status  string         `json:"status"`
	Matches []engine.Match `json:"matches,omitempty"`
	SHA256  string         `json:"sha256,omitempty"`
	Size    int64          `json:"size"`
}

// YARARules is an immutable set of rule sources. A scan names the set it
// started with, so a running scan finishes on it even after the ruleset sync
// swaps in a new one.
type YARARules struct {
	id      uint64
	sources []yara.RuleSource
}

var yaraRulesSeq atomic.Uint64

// NewYARARules returns a rule set; the sources are not copied and must not
// change afterwards.
func NewYARARules(sources []yara.RuleSource) *YARARules {
	return &YARARules{id: yaraRulesSeq.Add(1), sources: sources}
}

// YARAScan is one file to scan.
type YARAScan struct {
	File *os.File // read only through its descriptor; the caller closes it
	Size int64
	// Path fills the filename/filepath/extension externals. The worker
	// never opens it.
	Path string
	// RulesetIDs limits the scan to these rulesets; nil means all.
	RulesetIDs []string
	Timeout    time.Duration // 0: DefaultYARATimeout
}

// compileGrace bounds a worker's whole compile: the engine's own timeout
// per ruleset, plus this.
const compileGrace = 30 * time.Second

// CompileYARA compiles r in a worker and returns how each ruleset compiled.
// That worker keeps the compiled rules; the others compile r before their
// next scan with it. The error is set when no worker could compile at all
// (worker_unavailable), not when a ruleset failed (see CompileResult.Error).
func (p *Pool) CompileYARA(ctx context.Context, r *YARARules) ([]yara.CompileResult, error) {
	w, err := p.acquire(ctx)
	if err != nil {
		return nil, err
	}
	w.yaraID = 0 // compile even if it has r already: the caller wants the report
	res, err := p.loadYARA(ctx, w, r)
	if err != nil {
		p.discard(w, ctx.Err() == nil)
		return nil, err
	}
	p.release(w)
	return res, nil
}

// ScanYARA scans one file with r in a worker. A worker that takes longer
// than the timeout (plus a grace period) is killed; the result is then
// YARATimeout and the next file gets a new worker.
func (p *Pool) ScanYARA(ctx context.Context, r *YARARules, s YARAScan) YARAResult {
	if s.Timeout <= 0 {
		s.Timeout = DefaultYARATimeout
	}
	failed := YARAResult{Status: YARAWorkerFailed, Size: s.Size}
	w, err := p.acquire(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return YARAResult{Status: YARATimeout, Size: s.Size}
		}
		return failed
	}
	if _, err := p.loadYARA(ctx, w, r); err != nil {
		p.discard(w, ctx.Err() == nil)
		return failed
	}
	w.nextID++
	id := w.nextID
	m := message{Type: typeYARAScan, ID: id, Size: s.Size, Path: s.Path, RulesetIDs: s.RulesetIDs, TimeoutMS: s.Timeout.Milliseconds()}
	if err := w.sendScan(m, s.File); err != nil {
		p.discard(w, true)
		return failed
	}
	reply, err := w.await(ctx, time.Now().Add(s.Timeout+scanGrace))
	switch {
	case errors.Is(err, errScanTimeout):
		p.discard(w, false) // a slow rule or file, not a broken worker
		return YARAResult{Status: YARATimeout, Size: s.Size}
	case err != nil:
		p.discard(w, ctx.Err() == nil)
		return failed
	case reply.Type != typeResult || reply.ID != id || reply.YARA == nil:
		p.discard(w, true)
		return failed
	}
	p.release(w)
	return *reply.YARA
}

// loadYARA makes sure w has r compiled.
func (p *Pool) loadYARA(ctx context.Context, w *worker, r *YARARules) ([]yara.CompileResult, error) {
	if w.yaraID == r.id {
		return w.yaraCompiled, nil
	}
	for i := range r.sources {
		if err := w.c.writeMsg(message{Type: typeYARARuleset, Ruleset: &r.sources[i]}, -1); err != nil {
			return nil, err
		}
	}
	w.nextID++
	id := w.nextID
	if err := w.c.writeMsg(message{Type: typeYARACompile, ID: id}, -1); err != nil {
		return nil, err
	}
	budget := compileGrace + time.Duration(len(r.sources))*engine.DefaultCompileTimeout
	m, err := w.await(ctx, time.Now().Add(budget))
	if err != nil {
		return nil, err
	}
	if m.Type != typeYARACompiled || m.ID != id {
		return nil, fmt.Errorf("scanworker: unexpected %q reply to compile", m.Type)
	}
	w.yaraID, w.yaraCompiled = r.id, m.Compiled
	return m.Compiled, nil
}

// await reads w's next reply, waiting until deadline (or ctx's, if
// earlier). Past it the error is errScanTimeout.
func (w *worker) await(ctx context.Context, deadline time.Time) (message, error) {
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = w.c.setReadDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = w.c.setReadDeadline(time.Now()) })
	defer func() {
		stop()
		_ = w.c.setReadDeadline(time.Time{})
	}()
	m, extra, err := w.c.readMsg(maxFrameFromWorker)
	if extra != nil {
		_ = extra.Close()
	}
	if err != nil {
		if os.IsTimeout(err) {
			return message{}, errScanTimeout
		}
		return message{}, err
	}
	return m, nil
}

func closeFile(f *os.File) {
	if f != nil {
		_ = f.Close()
	}
}

// yaraState is a worker's YARA side: the sources received since the last
// compile, and the compiled rulesets.
type yaraState struct {
	pending []yara.RuleSource
	progs   []yaraProgram
}

type yaraProgram struct {
	id   string
	prog engine.Program
}

func (ys *yaraState) add(r *yara.RuleSource) {
	if r != nil {
		ys.pending = append(ys.pending, *r)
	}
}

// compile replaces the compiled rulesets with the pending ones.
func (ys *yaraState) compile() []yara.CompileResult {
	eng := engine.New(engine.Options{})
	out := make([]yara.CompileResult, 0, len(ys.pending))
	ys.progs = nil
	for _, src := range ys.pending {
		prog, skipped, err := eng.Compile(context.Background(), src.ID, src.Source)
		res := yara.CompileResult{ID: src.ID, Revision: src.Revision, Skipped: skipped[:min(len(skipped), yara.MaxSkippedRules)]}
		if err != nil {
			res.Error = yara.Truncate(err.Error(), yara.MaxErrorLen)
		} else {
			res.Rules = prog.RuleCount()
			ys.progs = append(ys.progs, yaraProgram{id: src.ID, prog: prog})
		}
		out = append(out, res)
	}
	ys.pending = nil
	return out
}

// scan runs the selected rulesets over f.
func (ys *yaraState) scan(f *os.File, m message) YARAResult {
	if f == nil {
		return YARAResult{Status: YARAWorkerFailed, Size: m.Size}
	}
	defer closeFile(f)
	var progs []yaraProgram
	want := map[string]bool{}
	for _, id := range m.RulesetIDs {
		want[id] = true
	}
	for _, p := range ys.progs {
		if len(want) == 0 || want[p.id] {
			progs = append(progs, p)
		}
	}
	if len(progs) == 0 {
		return YARAResult{Status: YARANoRules, Size: m.Size}
	}
	timeout := time.Duration(m.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = DefaultYARATimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	res := YARAResult{Status: YARAScanned}
	h := sha256.New()
	counted := &countWriter{}
	first := io.TeeReader(io.NewSectionReader(f, 0, m.Size), io.MultiWriter(h, counted))
	file := engine.File{Path: m.Path, Size: m.Size}
	for i, p := range progs {
		var r io.Reader = io.NewSectionReader(f, 0, m.Size)
		if i == 0 {
			r = first
		}
		ms, err := p.prog.ScanReader(ctx, r, file)
		if err == nil && i == 0 {
			// The engine may stop early; the hash covers the whole file.
			_, err = io.Copy(io.Discard, first)
		}
		if err != nil {
			res.Matches = nil
			res.Size = counted.n
			if ctx.Err() != nil {
				res.Status = YARATimeout
			} else {
				res.Status = YARAReadError
			}
			return res
		}
		for _, mt := range ms {
			if len(res.Matches) == MaxYARAMatches {
				break
			}
			mt.StringIDs = mt.StringIDs[:min(len(mt.StringIDs), yara.MaxStringIDs)]
			res.Matches = append(res.Matches, mt)
		}
	}
	res.SHA256 = hex.EncodeToString(h.Sum(nil))
	res.Size = counted.n
	return res
}

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}
