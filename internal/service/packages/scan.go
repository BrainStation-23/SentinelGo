package packages

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"sentinelgo/internal/sanitize"
)

// Bounds on one collection run. Files come from user-writable folders, so
// every read is capped and the run as a whole is bounded.
const (
	// maxManifestBytes caps one package.json, METADATA or installed.json
	// read. Real ones are a few KB; Composer's installed.json for a large
	// global install is a few hundred KB.
	maxManifestBytes = 4 << 20
	// maxFilesPerRun caps the files one run reads.
	maxFilesPerRun = 200_000
	// maxDirEntries caps the entries read from one directory.
	maxDirEntries = 50_000
)

// errTooLarge marks a file over the read cap.
var errTooLarge = errors.New("file too large")

// scan is the state of one collection run. complete turns false when
// something that exists could not be read (permissions, a cap, the deadline),
// so the result must not be used to retire packages the run didn't see.
type scan struct {
	ctx      context.Context
	pkgs     []Package
	files    int
	complete bool
}

func newScan(ctx context.Context) *scan {
	return &scan{ctx: ctx, complete: true}
}

func (s *scan) add(p Package) { s.pkgs = append(s.pkgs, p) }

// stopped reports whether the run must stop: ctx is done or the file budget
// is spent. Either makes the run incomplete.
func (s *scan) stopped() bool {
	if s.ctx.Err() != nil || s.files >= maxFilesPerRun {
		s.complete = false
		return true
	}
	return false
}

// readFile reads at most maxManifestBytes of path. A missing file is
// reported as not found without marking the run incomplete; any other
// failure (permissions, too large) does.
func (s *scan) readFile(path string) ([]byte, bool) {
	if s.stopped() {
		return nil, false
	}
	s.files++
	data, err := readLimited(path, maxManifestBytes)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.fail(path, err)
		}
		return nil, false
	}
	return data, true
}

// readDir lists dir. A missing directory is normal (the tool isn't
// installed); any other error marks the run incomplete.
func (s *scan) readDir(dir string) []os.DirEntry {
	if s.stopped() {
		return nil
	}
	f, err := os.Open(dir) // #nosec G304 -- a fixed install location under a user home
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.fail(dir, err)
		}
		return nil
	}
	defer func() { _ = f.Close() }()
	entries, err := f.ReadDir(maxDirEntries)
	if err != nil && !errors.Is(err, io.EOF) {
		s.fail(dir, err)
	}
	if len(entries) == maxDirEntries {
		s.complete = false
	}
	return entries
}

// glob expands pattern. Patterns are fixed install locations with at most a
// version wildcard, so the match list is small.
func (s *scan) glob(pattern string) []string {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		// Only a malformed pattern fails, which is a bug in the roots list.
		log.Printf("[packages] bad location pattern %s: %v", sanitize.ForLog(pattern), err)
		return nil
	}
	return matches
}

func (s *scan) fail(path string, err error) {
	s.complete = false
	log.Printf("[packages] cannot read %s: %v", sanitize.ForLog(path), sanitize.ForLog(err.Error()))
}

// readLimited reads path, refusing files over limit bytes.
func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- manifest paths under fixed install locations
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errTooLarge
	}
	return data, nil
}

// isDir reports whether e is a real directory. Symlinks and junctions are
// not followed: `npm link` and similar point into a user's own projects, and
// a link can lead onto a network or cloud-synced drive.
func isDir(e os.DirEntry) bool {
	return e.Type()&fs.ModeSymlink == 0 && e.IsDir()
}
