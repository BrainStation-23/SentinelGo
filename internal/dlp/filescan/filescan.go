// Package filescan finds sensitive data in files for file DLP (epic #324,
// #327). It detects a file's type from its content (not its name), extracts
// the text, and streams that text through the policy's detect.Engine in
// chunks. It doesn't care where the bytes come from (a file hook, an upload
// body), and it decides nothing: the caller applies the policy, including
// on_unscannable and on_timeout, to the Result.
//
// Privacy (#341): the file's content and extracted text never leave this
// package. They are not logged, returned, or written to disk; the only disk
// write is a spill of the raw file into the caller's root-only directory when
// a format needs random access, deleted as soon as the scan ends. A Result
// carries findings the way the clipboard does: detector ids, counts, masked
// matches and hashes.
//
// Hostile input: every reader is bounded (file, text, archive entries, depth,
// compression ratio) and the scan stops at the deadline. Parsing runs in the
// calling process; the sandboxed worker (#328) is a separate step.
package filescan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"time"

	"sentinelgo/internal/dlp/detect"
	"sentinelgo/internal/dlp/policy"
)

// Scan statuses (contract #326).
const (
	StatusScanned   = "scanned"
	StatusTruncated = "truncated" // the text limit was reached; the rest wasn't scanned
	StatusTimeout   = "timeout"
)

// Why a file couldn't be scanned; the status is "unscannable:<reason>".
const (
	ReasonEncrypted         = "encrypted"
	ReasonPasswordProtected = "password_protected"
	ReasonRightsProtected   = "rights_protected"
	ReasonTooLarge          = "too_large"
	ReasonUnsupportedType   = "unsupported_type"
	ReasonCorrupt           = "corrupt"
)

const unscannablePrefix = "unscannable:"

// Unscannable is the status for a file that couldn't be scanned for reason.
func Unscannable(reason string) string { return unscannablePrefix + reason }

// IsUnscannable reports whether status is an unscannable status.
func IsUnscannable(status string) bool {
	return len(status) > len(unscannablePrefix) && status[:len(unscannablePrefix)] == unscannablePrefix
}

// Limits bound what one scan may cost.
type Limits struct {
	MaxFileBytes int64         // larger files are unscannable:too_large without being read
	MaxTextBytes int           // extracted text scanned per file (an archive shares one budget)
	Timeout      time.Duration // the whole scan; then the status is timeout

	MaxDepth        int   // archives inside archives
	MaxEntries      int   // archive entries, over all nesting levels
	MaxArchiveBytes int64 // bytes decompressed from archives, over all nesting levels
	MaxRatio        int64 // uncompressed / compressed size of one entry
}

// Archive limits, the same for every bundle.
const (
	DefaultMaxDepth   = 3
	DefaultMaxEntries = 1000
	DefaultMaxRatio   = 100
	// maxDirEntries is how many entries a zip may declare before its central
	// directory is even read (archive/zip allocates one record per entry).
	maxDirEntries = 10000
)

// LimitsFrom builds the limits for a normalized bundle's files module.
func LimitsFrom(m policy.FilesModule) Limits {
	return Limits{
		MaxFileBytes:    m.MaxFileBytes,
		MaxTextBytes:    m.MaxTextBytes,
		Timeout:         time.Duration(m.ScanTimeoutMs) * time.Millisecond,
		MaxDepth:        DefaultMaxDepth,
		MaxEntries:      DefaultMaxEntries,
		MaxArchiveBytes: 4 * m.MaxFileBytes,
		MaxRatio:        DefaultMaxRatio,
	}
}

// Source describes the bytes being scanned.
type Source struct {
	Size int64 // -1 when unknown (e.g. a streamed upload)
}

// Result is the outcome of one scan.
type Result struct {
	Status       string
	DetectedType string           // e.g. "ooxml.xlsx", "text.utf16le", "archive.zip"
	Findings     []detect.Finding // in the file's own text; offsets index its extracted text
	TextBytes    int              // extracted text scanned, over the file and its entries
	Size         int64
	SHA256       string   // of the whole file; "" when it wasn't read in full
	Labels       []string // Microsoft sensitivity label names (unencrypted Office files)
	// Entries are archive members (nested ones as "outer.zip/inner.docx")
	// that had findings or couldn't be scanned in full. The caller evaluates
	// the policy per entry: an archive's verdict is the worst of its entries.
	Entries  []Entry
	Duration time.Duration
}

// Entry is one archive member's outcome.
type Entry struct {
	Name         string
	DetectedType string
	Status       string
	Findings     []detect.Finding
	Labels       []string
}

// Scanner scans files with one policy's engine. It is safe for concurrent use.
type Scanner struct {
	engine   *detect.Engine
	limits   Limits
	spillDir string

	// chunk and overlap size the text chunks; tests make them small.
	chunk, overlap int
}

// memSpillLimit is the largest input kept in memory when it must be read in
// full; bigger ones are spilled to spillDir.
const memSpillLimit = 4 << 20

// chunkOverlap is how much text two chunks share, so a match across a chunk
// boundary is still found (matches longer than half of it may be missed).
const chunkOverlap = 4 << 10

// New returns a Scanner. engine is the policy's file engine (it must scan at
// least policy.FileChunkBytes at a time) and may be nil when no policy applies
// to files: files are then only typed and hashed. spillDir must be a directory
// only the service can read (it receives raw file content); "" means inputs
// that need spilling are unscannable:too_large.
func New(engine *detect.Engine, limits Limits, spillDir string) *Scanner {
	return &Scanner{engine: engine, limits: limits, spillDir: spillDir, chunk: policy.FileChunkBytes, overlap: chunkOverlap}
}

// readerAtSized is an input that supports random access, e.g. an *os.File
// the service opened.
type readerAtSized interface {
	io.Reader
	io.ReaderAt
}

// Scan scans r. When r also implements io.ReaderAt (an *os.File), src.Size
// must be its size and it is read in place; otherwise it is read once into
// memory or a spill file. The deadline is ctx's or Limits.Timeout, whichever
// is first.
func (s *Scanner) Scan(ctx context.Context, src Source, r io.Reader) Result {
	start := time.Now()
	res := s.scan(ctx, src, r)
	res.Duration = time.Since(start)
	return res
}

func (s *Scanner) scan(ctx context.Context, src Source, r io.Reader) Result {
	res := Result{Size: src.Size}
	if src.Size > s.limits.MaxFileBytes {
		res.Status = Unscannable(ReasonTooLarge)
		return res
	}
	if s.limits.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.limits.Timeout)
		defer cancel()
	}

	in, err := s.materialize(ctx, src, r)
	if err != nil {
		res.Status = statusFor(ctx, err)
		return res
	}
	defer in.close()
	res.Size, res.SHA256 = in.size, in.sha256

	st := &scanState{s: s, ctx: ctx, textLeft: s.limits.MaxTextBytes, archiveLeft: s.limits.MaxArchiveBytes, entriesLeft: s.limits.MaxEntries}
	doc := st.scanDoc(in.ra, in.size, 0, "")
	res.Status, res.DetectedType, res.Findings, res.Labels = doc.status, doc.typ, doc.findings, doc.labels
	res.Entries = st.entries
	res.TextBytes = s.limits.MaxTextBytes - st.textLeft
	for _, e := range res.Entries {
		res.Status = worse(res.Status, e.Status)
	}
	return res
}

// input is the file as random-access bytes.
type input struct {
	ra     io.ReaderAt
	size   int64
	sha256 string
	close  func()
}

// materialize turns r into random-access bytes and hashes it.
func (s *Scanner) materialize(ctx context.Context, src Source, r io.Reader) (*input, error) {
	if ra, ok := r.(readerAtSized); ok && src.Size >= 0 {
		h := sha256.New()
		if _, err := io.Copy(h, ctxReader{ctx, io.NewSectionReader(ra, 0, src.Size)}); err != nil {
			return nil, err
		}
		return &input{ra: ra, size: src.Size, sha256: hex.EncodeToString(h.Sum(nil)), close: func() {}}, nil
	}
	h := sha256.New()
	body := io.TeeReader(ctxReader{ctx, io.LimitReader(r, s.limits.MaxFileBytes+1)}, h)
	ra, size, cleanup, err := s.spill(body, src.Size)
	if err != nil {
		return nil, err
	}
	if size > s.limits.MaxFileBytes {
		cleanup()
		return nil, errTooLarge
	}
	return &input{ra: ra, size: size, sha256: hex.EncodeToString(h.Sum(nil)), close: cleanup}, nil
}

// spill reads r in full: into memory when it fits in memSpillLimit, else into
// a new file in spillDir, which cleanup closes and deletes. Memory grows with
// what is actually read, so an archive entry that claims a large size but
// holds a few bytes costs a few bytes; sizeHint (-1 when unknown) only
// presizes the buffer, up to spillPresize.
//
// Spill files hold raw file content: spillDir must be readable by the service
// only, and the service should empty it at start in case a crash left one.
func (s *Scanner) spill(r io.Reader, sizeHint int64) (io.ReaderAt, int64, func(), error) {
	var buf bytes.Buffer
	if sizeHint > 0 {
		buf.Grow(int(min(sizeHint+1, spillPresize)))
	}
	n, err := io.Copy(&buf, io.LimitReader(r, memSpillLimit+1))
	if err != nil {
		return nil, 0, nil, err
	}
	if n <= memSpillLimit {
		return bytes.NewReader(buf.Bytes()), n, func() {}, nil
	}
	if s.spillDir == "" {
		return nil, 0, nil, errTooLarge
	}
	f, err := os.CreateTemp(s.spillDir, "scan-*")
	if err != nil {
		return nil, 0, nil, err
	}
	cleanup := func() { _ = f.Close(); _ = os.Remove(f.Name()) }
	size, err := io.Copy(f, io.MultiReader(&buf, r))
	if err != nil {
		cleanup()
		return nil, 0, nil, err
	}
	return f, size, cleanup, nil
}

// spillPresize caps how much spill allocates up front from a size hint.
const spillPresize = 64 << 10

var (
	errTooLarge = errors.New("too large")
	errCorrupt  = errors.New("corrupt")
)

// statusFor maps an error that ended a scan to its status.
func statusFor(ctx context.Context, err error) string {
	switch {
	case ctx.Err() != nil, errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return StatusTimeout
	case errors.Is(err, errTooLarge):
		return Unscannable(ReasonTooLarge)
	default:
		return Unscannable(ReasonCorrupt)
	}
}

// rank orders statuses from best to worst for worse().
func rank(status string) int {
	switch {
	case status == StatusScanned, status == "":
		return 0
	case status == StatusTruncated:
		return 1
	case IsUnscannable(status):
		return 2
	default: // timeout
		return 3
	}
}

// worse returns the worse of two statuses.
func worse(a, b string) string {
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// ctxReader stops reading once ctx is done.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
