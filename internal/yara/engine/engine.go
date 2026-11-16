// Package engine is the agent's YARA engine: a small wrapper around
// github.com/cawalch/go-yara (pure Go, no cgo). It is the only package that
// imports go-yara (enforced by TestOnlyEngineImportsGoYara), so the engine
// can be replaced without touching the rest of the agent.
//
// Matches carry rule and string identifiers only. go-yara can report the
// matched bytes; this package never asks for them and has nowhere to put
// them (see TestMatchCarriesNoBytes).
package engine

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/cawalch/go-yara/compiler"

	"sentinelgo/internal/dlp/filescan"
	"sentinelgo/internal/yara"
)

// goYaraModule is the module path; EngineVersion reads its version from the
// build info. pinnedVersion is the go.mod pin, for builds without module
// information (TestPinnedVersionMatchesGoMod keeps the two in step).
const (
	goYaraModule  = "github.com/cawalch/go-yara"
	pinnedVersion = "v0.10.0"
)

// Name is the engine name the bundle's engine.name refers to.
const Name = "go-yara"

// Defaults for New.
const (
	DefaultCompileTimeout = 30 * time.Second
	// DefaultMaxRules caps one ruleset. A 20 000-rule ruleset compiles in
	// about 1.5 s on a laptop; 10 000 keeps the slowest devices well inside
	// the compile timeout.
	DefaultMaxRules = 10000
)

// Errors Compile returns for a ruleset it won't load at all.
var (
	ErrInclude      = errInclude
	ErrTooManyRules = errors.New("yara: ruleset has more rules than the engine allows")
	ErrTimeout      = errors.New("yara: compile timed out")
	ErrNoRules      = errors.New("yara: no rule in the ruleset compiled")
)

// Skip reasons (SkippedRule.Reason). unsupported_module is followed by
// ":<module>".
const (
	ReasonUnsupportedModule = "unsupported_module"
	ReasonSyntax            = "syntax"
	ReasonSemantic          = "semantic"
	ReasonTooComplex        = "too_complex"
)

// Engine compiles rulesets.
type Engine interface {
	// Compile compiles one ruleset's source; id becomes the namespace of its
	// matches. Rules that can't compile (e.g. ones using `import "pe"`) are
	// skipped and returned, not fatal. It fails when nothing compiles, the
	// source uses include, it has more rules than the cap, or compiling
	// takes longer than the timeout.
	Compile(ctx context.Context, id string, src []byte) (Program, []yara.SkippedRule, error)
	// Version is the engine version reported in the status.
	Version() string
}

// Program is a compiled ruleset. It is immutable and safe for concurrent
// scans.
type Program interface {
	// ScanReader scans r, which holds the file f describes, and returns the
	// rules that matched. It reads at most f.Size bytes when f.Size > 0, and
	// buffers a bounded window, never the whole file.
	ScanReader(ctx context.Context, r io.Reader, f File) ([]Match, error)
	RuleCount() int
}

// File describes the file being scanned; it fills the standard externals.
type File struct {
	Path string // filepath; filename and extension are derived from it
	Size int64  // bytes to scan, 0 for "until EOF"
	// Type is the filescan type (e.g. "executable.pe", "text.utf8"); empty
	// means sniff it from the first bytes.
	Type string
}

// Match is one matching rule. It holds identifiers only: no matched bytes,
// offsets or context.
type Match struct {
	Rule      string         `json:"rule"`
	Namespace string         `json:"namespace"`
	Tags      []string       `json:"tags,omitempty"`
	Meta      map[string]any `json:"meta,omitempty"`
	StringIDs []string       `json:"string_ids,omitempty"`
}

// Options configure New.
type Options struct {
	CompileTimeout time.Duration // 0: DefaultCompileTimeout
	MaxRules       int           // 0: DefaultMaxRules
}

// New returns the go-yara engine.
func New(o Options) Engine {
	if o.CompileTimeout <= 0 {
		o.CompileTimeout = DefaultCompileTimeout
	}
	if o.MaxRules <= 0 {
		o.MaxRules = DefaultMaxRules
	}
	return &goYara{opts: o}
}

type goYara struct{ opts Options }

// EngineVersion is go-yara's version without the leading v, e.g. "0.9.0".
func EngineVersion() string {
	v := pinnedVersion
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == goYaraModule {
				v = d.Version
				if d.Replace != nil && d.Replace.Version != "" {
					v = d.Replace.Version
				}
			}
		}
	}
	return strings.TrimPrefix(v, "v")
}

func (g *goYara) Version() string { return EngineVersion() }

// noIncludeDir is the compiler's base directory for include. It can't be
// resolved (NUL is invalid in a path on every OS), so go-yara fails any
// include before opening a file, even one prepare's lexer missed.
const noIncludeDir = "\x00no-includes"

func (g *goYara) Compile(ctx context.Context, id string, src []byte) (Program, []yara.SkippedRule, error) {
	if len(src) > yara.MaxRulesetBytes {
		return nil, nil, fmt.Errorf("yara: ruleset is %d bytes, over the %d byte limit", len(src), yara.MaxRulesetBytes)
	}
	c := compiler.NewCompiler(
		compiler.WithIgnoreInvalidRules(true),
		compiler.WithWarnings(false),
		compiler.WithMaxInputSize(yara.MaxRulesetBytes+1<<10),
		compiler.WithMaxIncludeSize(1),
	)
	c.SetBaseDir(noIncludeDir)
	supported := map[string]bool{}
	for name := range c.GetOptions().Modules {
		supported[name] = true
	}
	source, imported, err := prepare(string(src), supported)
	if err != nil {
		return nil, nil, err
	}
	deadline := time.Now().Add(g.opts.CompileTimeout)
	cctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	prog, err := c.CompileSourceWithContext(cctx, source)
	skipped := skippedRules(c.GetIgnoredRules())
	if err == nil && !time.Now().Before(deadline) && ctx.Err() == nil {
		// Finished, but over the budget: a device this slow would hit the
		// timeout on the next compile anyway, so fail now, consistently.
		err = context.DeadlineExceeded
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			return nil, skipped, ErrTimeout
		}
		if ctx.Err() != nil {
			return nil, skipped, ctx.Err()
		}
		return nil, skipped, fmt.Errorf("yara: compile: %s", yara.Truncate(err.Error(), yara.MaxErrorLen))
	}
	n := prog.GetRuleCount()
	switch {
	case n > g.opts.MaxRules:
		return nil, skipped, fmt.Errorf("%w (%d > %d)", ErrTooManyRules, n, g.opts.MaxRules)
	case n == 0:
		return nil, skipped, ErrNoRules
	}
	return &program{prog: prog, ns: id, wholePE: imported["pe"]}, skipped, nil
}

// skippedRules maps go-yara's ignored rules to the status's skipped rules
// with a stable reason code. A rule skipped because it depends on a skipped
// rule gets that rule's reason.
func skippedRules(ignored []compiler.IgnoredRule) []yara.SkippedRule {
	reasons := make(map[string]string, len(ignored))
	out := make([]yara.SkippedRule, 0, len(ignored))
	for _, ig := range ignored {
		r := reason(ig, reasons)
		reasons[ig.Rule] = r
		out = append(out, yara.SkippedRule{Rule: ig.Rule, Line: ig.Line, Reason: r})
	}
	return out
}

func reason(ig compiler.IgnoredRule, earlier map[string]string) string {
	switch ig.Phase {
	case "parsing":
		return ReasonSyntax
	case "codegen":
		return ReasonTooComplex
	case "dependency":
		if r, ok := earlier[ig.Dependency]; ok {
			return r
		}
		return ReasonSemantic
	}
	if ig.Code == "unsupported-module" {
		if _, mod, ok := strings.Cut(ig.Message, "unsupported module: "); ok && mod != "" {
			return ReasonUnsupportedModule + ":" + yara.Truncate(mod, 64)
		}
		return ReasonUnsupportedModule
	}
	return ReasonSemantic
}

type program struct {
	prog *compiler.CompiledProgram
	ns   string
	// wholePE: the ruleset imports pe, so PE files are scanned from one
	// buffer holding the whole file (see scanWhole).
	wholePE bool
}

// typePE is filescan's type for a PE image.
const typePE = "executable.pe"

// go-yara's reader scans keep only the first streamPrefix bytes for the pe
// module: fields past it (signatures, checksum, resources, version info, and
// imports/exports stored late in the file) are undefined, so rules testing
// them never match. PE files between streamPrefix and MaxWholePEBytes are
// read into memory and scanned whole instead; larger ones still stream. The
// worker's memory limit is 1 GiB and it scans one file at a time.
const (
	streamPrefix    = 64 << 10
	MaxWholePEBytes = 64 << 20
)

// scanWhole reports whether f is scanned from one whole-file buffer.
func (p *program) scanWhole(f File) bool {
	return p.wholePE && f.Type == typePE && f.Size > streamPrefix && f.Size <= MaxWholePEBytes
}

// peOffset is e_lfanew, the offset of the "PE\0\0" signature, in an "MZ"
// file's DOS header; ok is false for anything else.
func peOffset(b []byte) (off int64, ok bool) {
	if len(b) < 0x40 || b[0] != 'M' || b[1] != 'Z' {
		return 0, false
	}
	return int64(binary.LittleEndian.Uint32(b[0x3c:])), true
}

// peOffsetBeyond reports an "MZ" head whose PE signature offset is past the
// head but inside a file of size bytes, so only the whole file can say
// whether it's a PE.
func peOffsetBeyond(head []byte, size int64) bool {
	off, ok := peOffset(head)
	return ok && off+4 > int64(len(head)) && off+4 <= size
}

// hasPESignature reports a whole "MZ" file with "PE\0\0" at e_lfanew.
func hasPESignature(data []byte) bool {
	off, ok := peOffset(data)
	return ok && off >= 4 && off+4 <= int64(len(data)) && string(data[off:off+4]) == "PE\x00\x00"
}

// readWhole reads up to n bytes of r, checking ctx between chunks. A file
// that shrank returns what it has.
func readWhole(ctx context.Context, r io.Reader, n int64) ([]byte, error) {
	const chunk = 1 << 20
	buf := make([]byte, n)
	var off int64
	for off < n {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m, err := io.ReadFull(r, buf[off:min(off+chunk, n)])
		off += int64(m)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return buf[:off], nil
}

func (p *program) RuleCount() int { return p.prog.GetRuleCount() }

// sniffBytes is how much ScanReader peeks at to type a file. It stays in the
// bufio buffer and is scanned with the rest.
const sniffBytes = 8 << 10

func (p *program) ScanReader(ctx context.Context, r io.Reader, f File) ([]Match, error) {
	if f.Size > 0 {
		r = io.LimitReader(r, f.Size)
	}
	// farPE: an "MZ" file whose PE signature offset lies past the sniffed
	// head, so SniffType couldn't confirm it (and may have typed it as text).
	farPE := false
	if f.Type == "" {
		br := bufio.NewReaderSize(r, sniffBytes)
		head, _ := br.Peek(sniffBytes) // a short file returns what it has
		f.Type = filescan.SniffType(head)
		farPE = f.Type != typePE && peOffsetBeyond(head, f.Size)
		r = br
	}
	var data []byte
	// A far PE is read whole whatever the ruleset imports or the file's size
	// (up to MaxWholePEBytes): only the whole file can confirm it, and the
	// filetype external must say executable.pe for every rule.
	whole := p.scanWhole(f) || (farPE && f.Size <= MaxWholePEBytes)
	if whole {
		var err error
		if data, err = readWhole(ctx, r, f.Size); err != nil {
			return nil, err
		}
		if farPE && hasPESignature(data) {
			f.Type = typePE
		}
	}
	s := p.prog.NewScanner(
		compiler.WithMatchData(0),
		compiler.WithReportedMatchesOnly(),
		compiler.WithoutRuleResults(),
		compiler.WithExternalVariables(externals(f)),
	)
	defer s.Close()
	var res *compiler.ScanResult
	var err error
	if whole {
		res, err = s.ScanWithContext(ctx, data)
	} else {
		res, err = s.ScanReaderWithContext(ctx, r)
	}
	if err != nil {
		return nil, err
	}
	out := make([]Match, 0, len(res.MatchedRules))
	for _, m := range res.MatchedRules {
		ids := make([]string, 0, len(m.Matches))
		for id := range m.Matches {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		out = append(out, Match{
			Rule:      m.Rule,
			Namespace: p.ns,
			Tags:      m.Tags,
			Meta:      m.Meta,
			StringIDs: ids,
		})
	}
	return out, nil
}

// externals are the values of the standard externals for f.
func externals(f File) map[string]any {
	name := filepath.Base(f.Path)
	if f.Path == "" {
		name = ""
	}
	return map[string]any{
		"filename":  name,
		"filepath":  f.Path,
		"extension": strings.ToLower(strings.TrimPrefix(filepath.Ext(name), ".")),
		"filetype":  f.Type,
	}
}
