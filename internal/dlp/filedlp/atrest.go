package filedlp

// At-rest classification (#331 part 2, modules.files.at_rest): scanning a
// file only when it moves is too late on Windows, where the copy has landed
// by then. So the agent also scans the files in the user folders in scope
// ahead of time, in the background, and keeps each verdict. When a program
// opens or copies such a file later, process taint and taint blocks take the
// stored verdict (verdict_source "at_rest") instead of scanning: a taint
// block starts as soon as the open is seen.
//
// What is stored, and where (#341): per file, a hash of its path, a
// signature of its listing (size and times) and its identity (volume, file
// id, size, times), and, only for a file with findings, the detector ids,
// counts and hashes of the first match, the detected type and the file's
// SHA-256. Never content, extracted text, masked matches or paths. The file
// is readable by SYSTEM and Administrators only.
//
// Keeping current: a full walk of the folders when the policy or the scope
// changes and every rescan_hours (unchanged files are skipped without being
// read), and in between the files the change journal reports (the NTFS USN
// journal on Windows), every journalPoll.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sentinelgo/internal/dlp/detect"
	"sentinelgo/internal/dlp/filescan"
	"sentinelgo/internal/dlp/policy"
	"sentinelgo/internal/dlp/scanworker"
	"sentinelgo/internal/winsec"
	"sentinelgo/internal/yara"
	"sentinelgo/internal/yara/walk"
)

// AtRestFile is the classification store's file in the config directory.
const AtRestFile = "dlp-at-rest.db"

// CapAtRest is at-rest classification's capability name in the DLP status.
const CapAtRest = "at_rest"

// VerdictAtRest is the verdict_source of a verdict taken from the store.
const VerdictAtRest = "at_rest"

// Tuning; vars for tests.
var (
	journalPoll      = 2 * time.Minute  // how often the change journal is read
	atRestSaveEvery  = 10 * time.Minute // a dirty store is saved at least this often
	maxAtRestEntries = 250_000          // files the store keeps
)

// atRestStoreVersion is the store file's format.
const atRestStoreVersion = 1

// atRestEntry is one file's verdict.
type atRestEntry struct {
	Sig   [16]byte // listing signature (size, times) under the policy version
	ID    [16]byte // identity key (identityKey)
	Seen  uint32   // the store generation that last saw the file
	Found *storedResult
}

// storedResult is what is kept of a scan with findings: no masked matches,
// no offsets, no entry names (only their extension).
type storedResult struct {
	Status       string
	DetectedType string
	SHA256       string
	Size         int64
	Findings     []storedFinding
	Entries      []storedEntry
}

type storedFinding struct {
	DetectorID string
	RuleID     string
	Count      int
	SHA256     string
}

type storedEntry struct {
	Ext          string
	DetectedType string
	Status       string
	Findings     []storedFinding
}

// JournalCursor is where a volume's change journal was last read.
type JournalCursor struct {
	Journal uint64 // the journal's id: a new journal means the old position is gone
	Next    int64  // the next record to read
}

// atRestState is what the store file holds.
type atRestState struct {
	Version  int
	Gen      uint32
	Policy   string // the policy version of the last full pass
	Roots    string // walk.RootsKey of its folders
	LastFull time.Time
	Entries  map[[16]byte]atRestEntry // by path hash
	Cursors  map[string]JournalCursor // by volume
}

// atRestStore is the verdicts, by path hash and by identity. It is safe for
// concurrent use.
type atRestStore struct {
	path string

	mu    sync.Mutex
	st    atRestState
	byID  map[[16]byte][16]byte // identity key → path hash
	found int                   // entries with findings
	dirty bool
	saved time.Time
}

// openAtRestStore loads the store at path. A missing or unreadable file is
// an empty store (the error is for the log); it is replaced on save.
func openAtRestStore(path string) (*atRestStore, error) {
	s := &atRestStore{path: path, saved: time.Now()}
	s.reset()
	f, err := os.Open(path) // #nosec G304 -- the agent's own data file
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	defer func() { _ = f.Close() }()
	var st atRestState
	if err := gob.NewDecoder(f).Decode(&st); err != nil {
		return s, fmt.Errorf("read the at-rest store: %w", err)
	}
	if st.Version != atRestStoreVersion {
		return s, nil
	}
	if st.Entries == nil {
		st.Entries = map[[16]byte]atRestEntry{}
	}
	if st.Cursors == nil {
		st.Cursors = map[string]JournalCursor{}
	}
	s.st = st
	for k, e := range st.Entries {
		s.byID[e.ID] = k
		if e.Found != nil {
			s.found++
		}
	}
	return s, nil
}

func (s *atRestStore) reset() {
	s.st = atRestState{Version: atRestStoreVersion, Entries: map[[16]byte]atRestEntry{}, Cursors: map[string]JournalCursor{}}
	s.byID = map[[16]byte][16]byte{}
	s.found = 0
}

// pathHash keys a path (case-insensitive: Windows).
func pathHash(p string) [16]byte {
	h := sha256.Sum256([]byte(strings.ToLower(p)))
	var k [16]byte
	copy(k[:], h[:16])
	return k
}

// listingSig is a listed file's signature under policy version.
func listingSig(k walk.Key, version string) [16]byte {
	h := sha256.New()
	var b [24]byte
	binary.LittleEndian.PutUint64(b[0:], uint64(k.Size))    // #nosec G115 -- bits for a hash
	binary.LittleEndian.PutUint64(b[8:], uint64(k.MTime))   // #nosec G115 -- bits for a hash
	binary.LittleEndian.PutUint64(b[16:], uint64(k.Change)) // #nosec G115 -- bits for a hash
	h.Write(b[:])
	h.Write([]byte(version))
	var sig [16]byte
	copy(sig[:], h.Sum(nil))
	return sig
}

// identityKey keys a file version under a policy version: the Decider's
// cache key, hashed.
func identityKey(id Identity, version string) [16]byte {
	h := sha256.New()
	var b [40]byte
	binary.LittleEndian.PutUint64(b[0:], id.Dev)
	binary.LittleEndian.PutUint64(b[8:], id.Ino)
	binary.LittleEndian.PutUint64(b[16:], uint64(id.Size))       // #nosec G115 -- bits for a hash
	binary.LittleEndian.PutUint64(b[24:], uint64(id.ModTime))    // #nosec G115 -- bits for a hash
	binary.LittleEndian.PutUint64(b[32:], uint64(id.ChangeTime)) // #nosec G115 -- bits for a hash
	h.Write(b[:])
	h.Write([]byte(version))
	var k [16]byte
	copy(k[:], h.Sum(nil))
	return k
}

// unchanged reports whether the file at ph was classified with sig, and
// marks it seen.
func (s *atRestStore) unchanged(ph, sig [16]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.st.Entries[ph]
	if !ok || e.Sig != sig {
		return false
	}
	if e.Seen != s.st.Gen {
		e.Seen = s.st.Gen
		s.st.Entries[ph] = e
		s.dirty = true
	}
	return true
}

// put stores a file's verdict. It reports false when the store is full.
func (s *atRestStore) put(ph, sig, id [16]byte, res filescan.Result) bool {
	found := keep(res)
	s.mu.Lock()
	defer s.mu.Unlock()
	old, had := s.st.Entries[ph]
	if !had && len(s.st.Entries) >= maxAtRestEntries {
		return false
	}
	if had {
		delete(s.byID, old.ID)
		if old.Found != nil {
			s.found--
		}
	}
	s.st.Entries[ph] = atRestEntry{Sig: sig, ID: id, Seen: s.st.Gen, Found: found}
	s.byID[id] = ph
	if found != nil {
		s.found++
	}
	s.dirty = true
	return true
}

// lookup returns the verdict for a file version under a policy version.
func (s *atRestStore) lookup(id Identity, version string) (filescan.Result, bool) {
	k := identityKey(id, version)
	s.mu.Lock()
	defer s.mu.Unlock()
	ph, ok := s.byID[k]
	if !ok {
		return filescan.Result{}, false
	}
	e := s.st.Entries[ph]
	if e.Found == nil {
		return filescan.Result{Status: filescan.StatusScanned, Size: id.Size}, true
	}
	return e.Found.result(), true
}

// beginPass starts a store generation: what the pass doesn't see is
// dropped by endPass.
func (s *atRestStore) beginPass() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Gen++
	s.dirty = true
}

// endPass records a finished full pass and drops the files it didn't see
// (deleted, moved out of scope).
func (s *atRestStore) endPass(version, roots string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.st.Entries {
		if e.Seen != s.st.Gen {
			delete(s.st.Entries, k)
			delete(s.byID, e.ID)
			if e.Found != nil {
				s.found--
			}
		}
	}
	s.st.Policy, s.st.Roots, s.st.LastFull = version, roots, at
	s.dirty = true
}

// lastPass returns the last full pass's policy version, folders and time.
func (s *atRestStore) lastPass() (string, string, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Policy, s.st.Roots, s.st.LastFull
}

// forget empties the store (classification turned off: nothing is kept).
func (s *atRestStore) forget() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.st.Entries) == 0 && s.st.LastFull.IsZero() {
		return
	}
	s.reset()
	s.dirty = true
}

// counts returns how many files have a verdict, and how many of those
// had findings.
func (s *atRestStore) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.st.Entries), s.found
}

func (s *atRestStore) cursors() map[string]JournalCursor {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]JournalCursor, len(s.st.Cursors))
	for k, v := range s.st.Cursors {
		out[k] = v
	}
	return out
}

func (s *atRestStore) setCursors(c map[string]JournalCursor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Cursors = c
	s.dirty = true
}

// save writes the store atomically, SYSTEM and Administrators only, when
// it changed.
func (s *atRestStore) save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create the at-rest store folder: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "dlp-at-rest-*.tmp")
	if err != nil {
		return fmt.Errorf("create the at-rest store: %w", err)
	}
	tmpPath := tmp.Name()
	err = tmp.Chmod(0o600)
	if err == nil {
		err = gob.NewEncoder(tmp).Encode(&s.st)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmpPath, s.path)
	}
	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write the at-rest store: %w", err)
	}
	if err := winsec.SecurePath(s.path); err != nil {
		return fmt.Errorf("restrict the at-rest store: %w", err)
	}
	s.dirty, s.saved = false, time.Now()
	return nil
}

// keep reduces a scan result to what the store may hold: nil for a file
// without findings.
func keep(res filescan.Result) *storedResult {
	if len(res.Findings) == 0 && !entriesFound(res.Entries) {
		return nil
	}
	out := &storedResult{Status: res.Status, DetectedType: res.DetectedType, SHA256: res.SHA256, Size: res.Size,
		Findings: keepFindings(res.Findings)}
	for _, e := range res.Entries {
		if len(e.Findings) == 0 {
			continue
		}
		out.Entries = append(out.Entries, storedEntry{Ext: fileExt(e.Name), DetectedType: e.DetectedType, Status: e.Status,
			Findings: keepFindings(e.Findings)})
	}
	return out
}

func entriesFound(es []filescan.Entry) bool {
	for _, e := range es {
		if len(e.Findings) > 0 {
			return true
		}
	}
	return false
}

func keepFindings(fs []detect.Finding) []storedFinding {
	out := make([]storedFinding, 0, len(fs))
	for _, f := range fs {
		out = append(out, storedFinding{DetectorID: f.DetectorID, RuleID: f.RuleID, Count: f.Count, SHA256: f.SHA256})
	}
	return out
}

// result turns a stored verdict back into a scan result for the policy
// evaluation. Entry names are only their extension, for type filters.
func (r *storedResult) result() filescan.Result {
	out := filescan.Result{Status: r.Status, DetectedType: r.DetectedType, SHA256: r.SHA256, Size: r.Size,
		Findings: findingsOf(r.Findings)}
	for _, e := range r.Entries {
		name := "entry"
		if e.Ext != "" {
			name += "." + e.Ext
		}
		out.Entries = append(out.Entries, filescan.Entry{Name: name, DetectedType: e.DetectedType, Status: e.Status,
			Findings: findingsOf(e.Findings)})
	}
	return out
}

func findingsOf(fs []storedFinding) []detect.Finding {
	out := make([]detect.Finding, 0, len(fs))
	for _, f := range fs {
		out = append(out, detect.Finding{DetectorID: f.DetectorID, RuleID: f.RuleID, Count: f.Count, SHA256: f.SHA256})
	}
	return out
}

// changeJournal reports the files changed on the folders' volumes since
// the last read (the NTFS USN journal on Windows).
type changeJournal interface {
	// Mark records each volume's current position, before a full pass,
	// so the changes made during it are read afterwards.
	Mark(roots []string, cursors map[string]JournalCursor) map[string]JournalCursor
	// Changes returns the paths changed under roots since cursors, and
	// the new cursors. lost is true when a volume's journal can't say
	// (a new journal, records already overwritten, too many changes):
	// walk again.
	Changes(ctx context.Context, roots []string, cursors map[string]JournalCursor) (paths []string, next map[string]JournalCursor, lost bool)
	// States reports each volume's journal: "active" or
	// "unsupported:<reason>".
	States() map[string]string
	Close()
}

// AtRestStatus is at-rest classification's state for the DLP status
// (files.at_rest).
type AtRestStatus struct {
	// State: running (a full pass), idle, off:no_taint (on, but neither
	// process taint nor taint blocks use it), disabled_locally,
	// unavailable:<reason>.
	State   string `json:"state"`
	Folders int    `json:"folders"` // folders in scope that exist
	// Files have a verdict; Sensitive of them had findings.
	Files     int `json:"files"`
	Sensitive int `json:"sensitive"`
	// LastFullPassAt is when the folders were last walked in full.
	LastFullPassAt *time.Time `json:"last_full_pass_at,omitempty"`
	// Scanned files were read since the agent started; Errors couldn't
	// be; StoreFull weren't kept (the store is bounded).
	Scanned   uint64 `json:"scanned"`
	Errors    uint64 `json:"errors"`
	StoreFull uint64 `json:"store_full,omitempty"`
	// Journal is each volume's change journal: active, or
	// unsupported:<reason> (the folders are then walked again every
	// rescan_hours only).
	Journal map[string]string `json:"journal,omitempty"`
}

// At-rest states.
const (
	atRestRunning  = "running"
	atRestIdle     = "idle"
	atRestNoTaint  = "off:no_taint"
	atRestLocalOff = "disabled_locally"
)

// atRestScanner scans one file (a sandboxed worker at background priority).
type atRestScanner interface {
	Scan(ctx context.Context, f *os.File, size int64, timeout time.Duration) filescan.Result
}

// atRestRunner keeps the store current.
type atRestRunner struct {
	store   *atRestStore
	scanner atRestScanner
	journal changeJournal // nil: full walks only
	goos    string
	// Seams: the policy in force (nil: none), whether the emergency
	// switch is on, the device's folders, removable and network drives,
	// opening a listed file with its identity, and power.
	compiled  func() *policy.Compiled
	localOff  func() bool
	env       walk.Env
	mounts    func() []walk.Mount
	open      func(walk.File) (*os.File, Identity, error)
	onBattery func() bool
	now       func() time.Time

	state                      atomic.Pointer[string]
	folders                    atomic.Int64
	busy                       atomic.Int64 // nanoseconds spent scanning: the CPU budget
	scanned, errors, storeFull atomic.Uint64
	kick                       chan struct{}
}

func newAtRestRunner(store *atRestStore, scanner atRestScanner, journal changeJournal, goos string) *atRestRunner {
	r := &atRestRunner{store: store, scanner: scanner, journal: journal, goos: goos,
		env: walk.DefaultEnv(), mounts: func() []walk.Mount { return nil }, onBattery: walk.OnBattery, now: time.Now,
		localOff: func() bool { return false }, kick: make(chan struct{}, 1)}
	idle := atRestIdle
	r.state.Store(&idle)
	return r
}

// poke makes the runner look at the policy now.
func (r *atRestRunner) poke() {
	select {
	case r.kick <- struct{}{}:
	default:
	}
}

func (r *atRestRunner) setState(s string) { r.state.Store(&s) }

// run keeps the store current until ctx ends, then saves it.
func (r *atRestRunner) run(ctx context.Context) {
	defer func() {
		if err := r.store.save(); err != nil {
			log.Printf("DLP: %v", err)
		}
		if r.journal != nil {
			r.journal.Close()
		}
	}()
	t := time.NewTicker(journalPoll)
	defer t.Stop()
	for {
		r.step(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-r.kick:
		}
	}
}

// step does what the policy asks for now: nothing, a full pass, or the
// journal's changes.
func (r *atRestRunner) step(ctx context.Context) {
	c := r.compiled()
	switch {
	case r.localOff():
		r.setState(atRestLocalOff)
		return
	case c == nil || !c.Modules.Files.WantsAtRest():
		r.setState(atRestIdle)
		r.store.forget() // off: keep nothing
		r.maybeSave()
		return
	case !c.Modules.Files.ClassifiesAtRest(r.goos):
		r.setState(atRestNoTaint)
		return
	}
	a := c.Modules.Files.AtRest
	o := r.walkOptions(c)
	r.folders.Store(int64(len(o.Roots)))
	rootsKey := walk.RootsKey(o.Roots)
	version, roots, last := r.store.lastPass()
	full := version != c.Version || roots != rootsKey || r.now().Sub(last) >= time.Duration(a.RescanHours)*time.Hour
	if !full && r.journal != nil {
		paths, next, lost := r.journal.Changes(ctx, o.Roots, r.store.cursors())
		r.store.setCursors(next)
		full = lost
		if !lost {
			r.classifyPaths(ctx, c, o, paths)
		}
	}
	if full {
		r.fullPass(ctx, c, o, rootsKey)
	}
	r.setState(atRestIdle)
	r.maybeSave()
}

func (r *atRestRunner) maybeSave() {
	r.store.mu.Lock()
	due := r.store.dirty && r.now().Sub(r.store.saved) >= atRestSaveEvery
	r.store.mu.Unlock()
	if due {
		if err := r.store.save(); err != nil {
			log.Printf("DLP: %v", err)
		}
	}
}

// walkOptions are the folders and limits for c.
func (r *atRestRunner) walkOptions(c *policy.Compiled) walk.Options {
	a := c.Modules.Files.AtRest
	roots := walk.Roots(yara.PresetCustom, a.FoldersFor(r.goos), r.env)
	limits := yara.Limits{MaxCPUPercent: a.MaxCPUPercent, SkipOnBattery: a.PausesOnBattery()}
	return walk.Options{
		GOOS: r.goos, Roots: roots, Exclude: walk.NewExcluder(a.Exclude[r.goos], "", r.env),
		MaxFileBytes: c.Modules.Files.MaxFileBytes, Mounts: r.mounts(),
		Guard: walk.NewThrottle(limits, r.onBattery, func() time.Duration { return time.Duration(r.busy.Load()) }),
	}
}

// errPolicyChanged stops a pass whose policy was replaced.
var errPolicyChanged = errors.New("at-rest: the policy changed")

// fullPass walks every folder and classifies new and changed files.
func (r *atRestRunner) fullPass(ctx context.Context, c *policy.Compiled, o walk.Options, rootsKey string) {
	r.setState(atRestRunning)
	if r.journal != nil {
		r.store.setCursors(r.journal.Mark(o.Roots, r.store.cursors()))
	}
	r.store.beginPass()
	start := r.now()
	_, err := walk.Walk(ctx, o, func(f walk.File) error {
		if cur := r.compiled(); cur == nil || cur.Version != c.Version || r.localOff() {
			return errPolicyChanged
		}
		r.classify(ctx, c, f)
		return nil
	})
	if err != nil {
		if !errors.Is(err, errPolicyChanged) && ctx.Err() == nil {
			log.Printf("DLP: at-rest classification pass stopped: %v", err)
		}
		return // not finished: the next step walks again (unchanged files are quick)
	}
	r.store.endPass(c.Version, rootsKey, start)
	if err := r.store.save(); err != nil {
		log.Printf("DLP: %v", err)
	}
}

// classifyPaths classifies the changed files the journal reported.
func (r *atRestRunner) classifyPaths(ctx context.Context, c *policy.Compiled, o walk.Options, paths []string) {
	for _, p := range paths {
		if ctx.Err() != nil {
			return
		}
		if _, ok := walk.Under(p, o.Roots, r.goos); !ok {
			continue
		}
		f, reason, err := walk.Stat(o, p)
		if err != nil || reason != "" {
			continue // gone, excluded, a link, a cloud placeholder, too large
		}
		if o.Guard != nil {
			if err := o.Guard.Wait(ctx); err != nil {
				return
			}
		}
		r.classify(ctx, c, f)
	}
}

// classify scans one listed file unless it is unchanged since its last
// verdict under this policy.
func (r *atRestRunner) classify(ctx context.Context, c *policy.Compiled, f walk.File) {
	ph, sig := pathHash(f.Path), listingSig(f.Key, c.Version)
	if r.store.unchanged(ph, sig) {
		return
	}
	fh, id, err := r.open(f)
	if err != nil {
		if !errors.Is(err, walk.ErrChanged) && !errors.Is(err, fs.ErrNotExist) {
			r.errors.Add(1)
		}
		return
	}
	defer func() { _ = fh.Close() }()
	start := r.now()
	res := r.scanner.Scan(ctx, fh, id.Size, time.Duration(c.Modules.Files.ScanTimeoutMs)*time.Millisecond)
	r.busy.Add(int64(r.now().Sub(start)))
	switch {
	case res.Status == filescan.StatusTimeout, res.Status == filescan.Unscannable(scanworker.ReasonWorkerFailed):
		r.errors.Add(1) // try again next time: not stored
		return
	}
	r.scanned.Add(1)
	if !r.store.put(ph, sig, identityKey(id, c.Version), res) {
		r.storeFull.Add(1)
	}
}

// status reports the runner's state.
func (r *atRestRunner) status() *AtRestStatus {
	files, sensitive := r.store.counts()
	s := &AtRestStatus{State: *r.state.Load(), Folders: int(r.folders.Load()), Files: files, Sensitive: sensitive,
		Scanned: r.scanned.Load(), Errors: r.errors.Load(), StoreFull: r.storeFull.Load()}
	if _, _, last := r.store.lastPass(); !last.IsZero() {
		at := last.UTC()
		s.LastFullPassAt = &at
	}
	if r.journal != nil {
		s.Journal = r.journal.States()
	}
	return s
}
