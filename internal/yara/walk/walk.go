package walk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"strings"
)

// Reasons a file or folder is skipped, counted in Stats.Skipped. Their sum
// is the scan's files_skipped.
const (
	SkipExcluded  = "excluded"          // always excluded, or the bundle's exclusions
	SkipLink      = "link"              // symlink, junction, mount point or other name surrogate
	SkipSpecial   = "special"           // device, pipe or socket
	SkipNetwork   = "network"           // network share (limits.include_network_mounts off)
	SkipRemovable = "removable"         // removable drive (limits.include_removable off)
	SkipTooLarge  = "too_large"         // over limits.max_file_bytes
	SkipCloud     = "cloud_placeholder" // content not on the device; reading would download it
	SkipTooDeep   = "too_deep"          // below MaxDepth
	SkipTCCDenied = "tcc_denied"        // macOS privacy (no Full Disk Access)
	SkipUnchanged = "unchanged"         // skip cache: same file, same rules
)

// DefaultMaxDepth is how many folders below a root the walk goes.
const DefaultMaxDepth = 64

// ErrPartial is returned when the guard stopped the walk (time or file
// limit); Stats.Checkpoint says where the next window resumes.
var ErrPartial = errors.New("walk: stopped at a scan limit")

// Mount is a removable drive or network share (filedlp.ExternalMounts).
type Mount struct {
	Path    string
	Network bool
}

// Guard is consulted before each file is handed out: it may wait (CPU
// budget, battery) and returns ErrLimitReached to stop. Throttle is the
// implementation.
type Guard interface {
	Wait(ctx context.Context) error
}

// Options configure a walk.
type Options struct {
	GOOS     string
	Roots    []string
	Exclude  *Excluder
	MaxDepth int // 0: DefaultMaxDepth
	// MaxFileBytes: larger files are skipped (too_large). 0: no limit.
	MaxFileBytes     int64
	Mounts           []Mount
	IncludeNetwork   bool
	IncludeRemovable bool
	// Cache, when set, skips files whose Key and Rules match the last
	// scan. On-demand scans leave it nil so admins can confirm a match is
	// still there.
	Cache *Cache
	Rules string
	Guard Guard
	// Resume continues a partial scan (ignored when the roots changed).
	Resume *Checkpoint
}

// Checkpoint is where a partial scan stopped: roots before Root are done,
// and in Root every file up to Path in walk order.
type Checkpoint struct {
	RootsKey string `json:"roots_key"`
	Root     int    `json:"root"`
	Path     string `json:"path"`
}

// File is one file to scan.
type File struct {
	Path string
	Size int64
	// Key is the skip cache key; store the scan result under it.
	Key Key
	id  fileID
}

// Stats count what a walk did.
type Stats struct {
	Files   int64            // handed to the callback
	Skipped map[string]int64 // by reason
	Errors  int64            // folders or files that couldn't be listed or read
	// TCCDenied: macOS refused a folder for privacy (no Full Disk Access).
	TCCDenied bool
	// Checkpoint is set when the walk returned ErrPartial.
	Checkpoint *Checkpoint
}

// FilesSkipped is the sum of the skip counts.
func (s Stats) FilesSkipped() int64 {
	var n int64
	for _, v := range s.Skipped {
		n += v
	}
	return n
}

// Test seams.
var (
	readDir = os.ReadDir
	lstat   = os.Lstat
)

// RootsKey identifies a root list, so a checkpoint isn't applied to a
// different scope.
func RootsKey(roots []string) string {
	h := sha256.Sum256([]byte(strings.Join(roots, "\x00")))
	return hex.EncodeToString(h[:8])
}

type walker struct {
	o       Options
	fn      func(File) error
	st      Stats
	mounts  map[string]Mount
	resume  string // skip files up to this path in walk order ("" when passed)
	root    int
	lastOut string
}

// Walk lists the files under o.Roots and calls fn for each, in a stable
// order (roots in order, each folder's entries by name). It never follows
// links and never reads a file. It stops at fn's first error (returning
// it), when ctx ends, or when the guard says a limit was reached
// (ErrPartial, with a checkpoint).
func Walk(ctx context.Context, o Options, fn func(File) error) (Stats, error) {
	if o.MaxDepth <= 0 {
		o.MaxDepth = DefaultMaxDepth
	}
	w := &walker{o: o, fn: fn, st: Stats{Skipped: map[string]int64{}}, mounts: map[string]Mount{}}
	for _, m := range o.Mounts {
		w.mounts[w.fold(m.Path)] = m
	}
	start := 0
	key := RootsKey(o.Roots)
	if r := o.Resume; r != nil && r.RootsKey == key && r.Root >= 0 && r.Root < len(o.Roots) {
		start, w.resume = r.Root, r.Path
	}
	for i := start; i < len(o.Roots); i++ {
		w.root, w.lastOut = i, ""
		if i > start {
			w.resume = ""
		}
		if err := w.walkRoot(ctx, o.Roots[i]); err != nil {
			if errors.Is(err, ErrLimitReached) {
				last := w.lastOut
				if last == "" && i == start {
					last = w.resume // nothing new handed out: keep the old position
				}
				w.st.Checkpoint = &Checkpoint{RootsKey: key, Root: i, Path: last}
				return w.st, ErrPartial
			}
			return w.st, err
		}
	}
	return w.st, nil
}

func (w *walker) walkRoot(ctx context.Context, root string) error {
	if reason, skip := w.mountSkip(root, true); skip {
		w.skip(reason)
		return nil
	}
	info, err := lstat(root)
	if err != nil {
		w.fail(err)
		return nil
	}
	if info.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
		w.skip(SkipLink)
		return nil
	}
	if w.o.Exclude.Excluded(root, baseName(root, w.o.GOOS)) {
		w.skip(SkipExcluded)
		return nil
	}
	if !info.IsDir() {
		return w.file(ctx, root, info)
	}
	return w.dir(ctx, root, 0)
}

func (w *walker) dir(ctx context.Context, dir string, depth int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := readDir(dir)
	if err != nil {
		w.fail(err)
		// ReadDir returns what it read before the error; keep going with it.
	}
	sep := separator(w.o.GOOS)
	for _, e := range entries {
		p := join(dir, e.Name(), sep)
		typ := e.Type()
		if w.resume != "" {
			if typ.IsDir() && within(w.resume, p, w.o.GOOS) {
				// The checkpoint is below this folder: go in.
			} else if compareWalkOrder(p, w.resume, sep) <= 0 {
				continue
			} else {
				w.resume = ""
			}
		}
		if w.o.Exclude.Excluded(p, e.Name()) {
			w.skip(SkipExcluded)
			continue
		}
		switch {
		case typ&(fs.ModeSymlink|fs.ModeIrregular) != 0:
			w.skip(SkipLink)
		case typ.IsDir():
			if reason, skip := w.mountSkip(p, false); skip {
				w.skip(reason)
				continue
			}
			if depth+1 > w.o.MaxDepth {
				w.skip(SkipTooDeep)
				continue
			}
			if err := w.dir(ctx, p, depth+1); err != nil {
				return err
			}
		case typ.IsRegular():
			info, err := e.Info()
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) { // gone since the listing
					w.fail(err)
				}
				continue
			}
			if err := w.file(ctx, p, info); err != nil {
				return err
			}
		default:
			w.skip(SkipSpecial)
		}
	}
	return nil
}

func (w *walker) file(ctx context.Context, p string, info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		w.skip(SkipSpecial)
		return nil
	}
	if placeholder(info) {
		w.skip(SkipCloud)
		return nil
	}
	if w.o.MaxFileBytes > 0 && info.Size() > w.o.MaxFileBytes {
		w.skip(SkipTooLarge)
		return nil
	}
	f := File{Path: p, Size: info.Size(), Key: keyOf(p, info), id: idOf(info)}
	if w.o.Cache != nil {
		if _, ok := w.o.Cache.Lookup(f.Key, w.o.Rules); ok {
			w.skip(SkipUnchanged)
			return nil
		}
	}
	if w.o.Guard != nil {
		if err := w.o.Guard.Wait(ctx); err != nil {
			return err
		}
	}
	if err := w.fn(f); err != nil {
		return err
	}
	w.st.Files++
	w.lastOut = p
	return nil
}

// mountSkip reports whether p is (or, for a root, is inside) a network
// share or removable drive the limits leave out.
func (w *walker) mountSkip(p string, root bool) (string, bool) {
	if w.o.GOOS == "windows" && strings.HasPrefix(p, `\\`) {
		return SkipNetwork, !w.o.IncludeNetwork
	}
	m, ok := w.mounts[w.fold(p)]
	if alt, has := firmlinked(p, w.o.GOOS); !ok && has {
		m, ok = w.mounts[w.fold(alt)]
	}
	if !ok && root {
		for _, mm := range w.o.Mounts {
			if within(p, mm.Path, w.o.GOOS) {
				m, ok = mm, true
				break
			}
		}
	}
	if !ok {
		return "", false
	}
	if m.Network {
		return SkipNetwork, !w.o.IncludeNetwork
	}
	return SkipRemovable, !w.o.IncludeRemovable
}

func (w *walker) fold(p string) string {
	p = clean(p, w.o.GOOS)
	if w.o.GOOS == "windows" {
		return strings.ToLower(p)
	}
	return p
}

func (w *walker) skip(reason string) { w.st.Skipped[reason]++ }

// fail counts a listing or stat error. macOS privacy refusals are skips,
// not errors (#413); a path that vanished is neither.
func (w *walker) fail(err error) {
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case privacyDenied(w.o.GOOS, err):
		w.st.TCCDenied = true
		w.skip(SkipTCCDenied)
	default:
		w.st.Errors++
	}
}

// compareWalkOrder orders two paths the way the walk visits them: segment
// by segment, by name, a folder before what is inside it.
func compareWalkOrder(a, b, sep string) int {
	as, bs := strings.Split(a, sep), strings.Split(b, sep)
	for i := 0; i < len(as) && i < len(bs); i++ {
		if c := strings.Compare(as[i], bs[i]); c != 0 {
			return c
		}
	}
	return len(as) - len(bs)
}

func baseName(p, goos string) string {
	p = strings.TrimRight(p, separator(goos))
	if i := strings.LastIndex(p, separator(goos)); i >= 0 {
		return p[i+1:]
	}
	return p
}
