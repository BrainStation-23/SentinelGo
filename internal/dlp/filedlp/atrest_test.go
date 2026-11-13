package filedlp

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sentinelgo/internal/dlp/detect"
	"sentinelgo/internal/dlp/filescan"
	"sentinelgo/internal/dlp/policy"
	"sentinelgo/internal/yara/walk"
)

func atRestBundle(t *testing.T, version string, enabled bool, dir string) string {
	t.Helper()
	folders, err := json.Marshal(map[string][]string{runtime.GOOS: {dir}})
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`{"schema_version": 1, "version": %q, "enabled": true, "evidence_mode": "masked",
	  "modules": {"files": {"enabled": true, "channels": {"file.removable": true},
	    "copy_correlation": {"process_taint": true},
	    "at_rest": {"enabled": %v, "folders": %s, "skip_on_battery": false}}},
	  "policies": [{"id": "p1", "name": "Cards", "channels": ["file.removable"], "action": "block",
	    "detectors": [{"id": "pii.credit_card", "rule_id": "r1", "min_count": 1}]}]}`, version, enabled, folders)
}

// fakeJournal reports the paths it's given, or that it lost track.
type fakeJournal struct {
	mu     sync.Mutex
	paths  []string
	lost   bool
	marks  int
	closed bool
}

func (j *fakeJournal) Mark([]string, map[string]JournalCursor) map[string]JournalCursor {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.marks++
	return map[string]JournalCursor{"X:": {Journal: 1, Next: int64(j.marks)}}
}

func (j *fakeJournal) Changes(_ context.Context, _ []string, c map[string]JournalCursor) ([]string, map[string]JournalCursor, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	p, lost := j.paths, j.lost
	j.paths, j.lost = nil, false
	return p, c, lost
}

func (j *fakeJournal) States() map[string]string { return map[string]string{"X:": "active"} }
func (j *fakeJournal) Close()                    { j.closed = true }

// fileIdentity stands in for the OS identity: the path's hash, size and
// modification time.
func fileIdentity(p string, fi os.FileInfo) Identity {
	h := pathHash(p)
	return Identity{Dev: 1, Ino: binary.LittleEndian.Uint64(h[:8]), Size: fi.Size(), ModTime: fi.ModTime().UnixNano(), ChangeTime: fi.ModTime().UnixNano()}
}

func openForTest(f walk.File) (*os.File, Identity, error) {
	fh, err := os.Open(f.Path)
	if err != nil {
		return nil, Identity{}, err
	}
	fi, err := fh.Stat()
	if err != nil {
		_ = fh.Close()
		return nil, Identity{}, err
	}
	return fh, fileIdentity(f.Path, fi), nil
}

type atRestFixture struct {
	dir     string
	r       *atRestRunner
	store   *atRestStore
	scanner *sensitiveScanner
	journal *fakeJournal
	c       *policy.Compiled
}

func newAtRestFixture(t *testing.T) *atRestFixture {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{"cards.xlsx": "4111 1111 1111 1111", "notes.txt": "nothing"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	store, err := openAtRestStore(filepath.Join(t.TempDir(), AtRestFile))
	if err != nil {
		t.Fatal(err)
	}
	fx := &atRestFixture{dir: dir, store: store, scanner: &sensitiveScanner{}, journal: &fakeJournal{}}
	fx.c = compile(t, atRestBundle(t, "v1", true, dir))
	fx.r = newAtRestRunner(store, fx.scanner, fx.journal, runtime.GOOS)
	fx.r.compiled = func() *policy.Compiled { return fx.c }
	fx.r.open = openForTest
	fx.r.onBattery = func() bool { return false }
	return fx
}

func (fx *atRestFixture) lookup(t *testing.T, name string) (filescan.Result, bool) {
	t.Helper()
	p := filepath.Join(fx.dir, name)
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fx.store.lookup(fileIdentity(p, fi), fx.c.Version)
}

func TestAtRest_FullPassThenJournal(t *testing.T) {
	fx := newAtRestFixture(t)
	ctx := context.Background()

	fx.r.step(ctx)
	st := fx.r.status()
	if fx.scanner.count() != 2 || st.Files != 2 || st.Sensitive != 1 || st.Folders != 1 || st.LastFullPassAt == nil || st.State != atRestIdle {
		t.Fatalf("after the first pass: scans %d status %+v", fx.scanner.count(), st)
	}
	if fx.journal.marks != 1 {
		t.Errorf("the journal position should be marked before a full pass: %d", fx.journal.marks)
	}
	res, ok := fx.lookup(t, "cards.xlsx")
	if !ok || len(res.Findings) != 1 || res.Findings[0].DetectorID != "pii.credit_card" || res.SHA256 == "" {
		t.Fatalf("cards verdict %v %+v", ok, res)
	}
	if res, ok := fx.lookup(t, "notes.txt"); !ok || len(res.Findings) != 0 || res.Status != filescan.StatusScanned {
		t.Fatalf("clean verdict %v %+v", ok, res)
	}

	// Nothing changed: no scan.
	fx.r.step(ctx)
	if fx.scanner.count() != 2 {
		t.Fatalf("an unchanged folder was scanned again: %d", fx.scanner.count())
	}

	// A changed file the journal reports is classified again; a path
	// outside the folders is ignored.
	p := filepath.Join(fx.dir, "notes.txt")
	if err := os.WriteFile(p, []byte("more text"), 0o600); err != nil {
		t.Fatal(err)
	}
	fx.journal.paths = []string{p, filepath.Join(t.TempDir(), "elsewhere.txt")}
	fx.r.step(ctx)
	if fx.scanner.count() != 3 {
		t.Fatalf("the changed file wasn't classified: %d scans", fx.scanner.count())
	}
	if _, ok := fx.lookup(t, "notes.txt"); !ok {
		t.Fatal("the new version has no verdict")
	}

	// A journal that lost track means a full pass (unchanged files are
	// still not read).
	fx.journal.lost = true
	fx.r.step(ctx)
	if fx.journal.marks != 2 || fx.scanner.count() != 3 {
		t.Fatalf("lost journal: marks %d scans %d", fx.journal.marks, fx.scanner.count())
	}
}

func TestAtRest_NewPolicyAndDeletedFiles(t *testing.T) {
	fx := newAtRestFixture(t)
	ctx := context.Background()
	fx.r.step(ctx)
	if err := os.Remove(filepath.Join(fx.dir, "notes.txt")); err != nil {
		t.Fatal(err)
	}
	// A new policy version classifies everything again (verdicts depend on
	// the detectors), and drops the files that are gone.
	fx.c = compile(t, atRestBundle(t, "v2", true, fx.dir))
	fx.r.step(ctx)
	if fx.scanner.count() != 3 {
		t.Fatalf("scans %d", fx.scanner.count())
	}
	if st := fx.r.status(); st.Files != 1 || st.Sensitive != 1 {
		t.Fatalf("status %+v", st)
	}
	if _, ok := fx.lookup(t, "cards.xlsx"); !ok {
		t.Fatal("no verdict under the new policy")
	}
}

func TestAtRest_OffForgetsAndSwitches(t *testing.T) {
	fx := newAtRestFixture(t)
	ctx := context.Background()
	fx.r.step(ctx)

	off := true
	fx.r.localOff = func() bool { return off }
	fx.r.step(ctx)
	if st := fx.r.status(); st.State != atRestLocalOff || st.Files != 2 {
		t.Fatalf("emergency switch: %+v", st)
	}
	off = false

	// Without process taint or taint blocks nothing would use the verdicts.
	fx.c = compile(t, strings.Replace(atRestBundle(t, "v1", true, fx.dir), `"process_taint": true`, `"process_taint": false`, 1))
	fx.r.step(ctx)
	if st := fx.r.status(); st.State != atRestNoTaint {
		t.Fatalf("no taint: %+v", st)
	}

	// Turned off: nothing is kept.
	fx.c = compile(t, atRestBundle(t, "v1", false, fx.dir))
	fx.r.step(ctx)
	if st := fx.r.status(); st.State != atRestIdle || st.Files != 0 || st.LastFullPassAt != nil {
		t.Fatalf("off: %+v", st)
	}
}

// run classifies when poked, and on the way out saves the store and closes
// the journal.
func TestAtRestRunner_Run(t *testing.T) {
	prev := journalPoll
	journalPoll = time.Hour
	t.Cleanup(func() { journalPoll = prev })
	fx := newAtRestFixture(t)
	var cur atomic.Pointer[policy.Compiled]
	cur.Store(compile(t, atRestBundle(t, "v1", false, fx.dir)))
	fx.r.compiled = cur.Load
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		fx.r.run(ctx)
	}()
	cur.Store(compile(t, atRestBundle(t, "v1", true, fx.dir)))
	deadline := time.Now().Add(10 * time.Second)
	for fx.r.status().Files != 2 {
		if time.Now().After(deadline) {
			t.Fatalf("not classified after a poke: %+v", fx.r.status())
		}
		fx.r.poke()
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	fx.journal.mu.Lock()
	closed := fx.journal.closed
	fx.journal.mu.Unlock()
	if !closed {
		t.Error("the journal wasn't closed")
	}
	s, err := openAtRestStore(fx.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if files, sensitive := s.counts(); files != 2 || sensitive != 1 {
		t.Errorf("saved store: %d files, %d sensitive", files, sensitive)
	}
}

func TestAtRestStore_SaveReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), AtRestFile)
	s, err := openAtRestStore(path)
	if err != nil {
		t.Fatal(err)
	}
	id := Identity{Dev: 7, Ino: 9, Size: 19, ModTime: 100, ChangeTime: 200}
	found := filescan.Result{Status: filescan.StatusScanned, DetectedType: "archive.zip", SHA256: strings.Repeat("ab", 32), Size: 19,
		Findings: []detect.Finding{{DetectorID: "pii.credit_card", Count: 2, Masked: "4111********1111", SHA256: "aa", Offsets: [][2]int{{1, 2}}}},
		Entries: []filescan.Entry{{Name: "q3/salaries.xlsx", DetectedType: "ooxml.xlsx", Status: filescan.StatusScanned,
			Findings: []detect.Finding{{DetectorID: "pii.ssn", Count: 1, Masked: "***-**-1234"}}}}}
	s.beginPass()
	if !s.put(pathHash(`C:\Users\ana\Documents\a.zip`), [16]byte{1}, identityKey(id, "v1"), found) {
		t.Fatal("put")
	}
	s.setCursors(map[string]JournalCursor{"C:": {Journal: 5, Next: 77}})
	s.endPass("v1", "roots", time.Unix(1000, 0))
	if err := s.save(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"4111", "1234", "salaries", "ana", "Documents"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the store holds %q", secret)
		}
	}

	s2, err := openAtRestStore(path)
	if err != nil {
		t.Fatal(err)
	}
	res, ok := s2.lookup(id, "v1")
	if !ok || res.DetectedType != "archive.zip" || len(res.Findings) != 1 || res.Findings[0].Masked != "" || res.Findings[0].Offsets != nil ||
		res.Findings[0].Count != 2 || len(res.Entries) != 1 || res.Entries[0].Name != "entry.xlsx" || res.Entries[0].Findings[0].DetectorID != "pii.ssn" {
		t.Fatalf("reloaded %v %+v", ok, res)
	}
	if _, ok := s2.lookup(id, "v2"); ok {
		t.Error("a verdict under another policy version was returned")
	}
	if c := s2.cursors(); c["C:"].Next != 77 {
		t.Errorf("cursors %+v", c)
	}
	if v, roots, at := s2.lastPass(); v != "v1" || roots != "roots" || !at.Equal(time.Unix(1000, 0)) {
		t.Errorf("last pass %q %q %v", v, roots, at)
	}
}

func TestAtRestStore_Bounded(t *testing.T) {
	prev := maxAtRestEntries
	maxAtRestEntries = 1
	t.Cleanup(func() { maxAtRestEntries = prev })
	s, _ := openAtRestStore(filepath.Join(t.TempDir(), AtRestFile))
	ok1 := s.put([16]byte{1}, [16]byte{1}, [16]byte{1}, filescan.Result{})
	ok2 := s.put([16]byte{2}, [16]byte{2}, [16]byte{2}, filescan.Result{})
	ok3 := s.put([16]byte{1}, [16]byte{3}, [16]byte{3}, filescan.Result{}) // an update still fits
	if !ok1 || ok2 || !ok3 {
		t.Fatalf("puts %v %v %v", ok1, ok2, ok3)
	}
}

func TestAtRestStore_Unreadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), AtRestFile)
	if err := os.WriteFile(path, []byte("not a store"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := openAtRestStore(path)
	if err == nil || s == nil {
		t.Fatalf("want an empty store and an error: %v", err)
	}
	if files, _ := s.counts(); files != 0 {
		t.Errorf("files %d", files)
	}
}

// The decider takes an at-rest verdict instead of scanning, for taint
// blocks and process taint.
func TestDecider_AtRestVerdicts(t *testing.T) {
	fastNotices(t)
	at := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	scanner := &sensitiveScanner{}
	sink := &recordingSink{}
	d := NewDecider(scanner, sink)
	d.SetUserNotifier(&fakeUserNotifier{readiness: map[string]string{"1": "supported"}})
	c := compile(t, netTaintBundle(false, true))
	d.Apply(c)
	// The file's name says "clean", so a scan would find nothing: only
	// the stored verdict can block.
	f, ident := tempFile(t, t.TempDir(), "report.docx")
	var asked []string
	d.SetAtRest(func(id Identity, version string) (filescan.Result, bool) {
		asked = append(asked, version)
		if id != ident {
			return filescan.Result{}, false
		}
		return filescan.Result{Status: filescan.StatusScanned, Size: id.Size, SHA256: strings.Repeat("ef", 32), Findings: []detect.Finding{cardFinding()}}, true
	})
	_, block := d.DecideNetworkTaint(context.Background(), Request{File: f, Path: f.Name(), Proc: chromeProc, Ident: ident, At: at})
	if !block || scanner.count() != 0 {
		t.Fatalf("block %v scans %d", block, scanner.count())
	}
	evs := sink.events()
	if len(evs) != 1 || evs[0].Scan.VerdictSource != VerdictAtRest || len(asked) != 1 || asked[0] != c.Version {
		t.Fatalf("events %+v asked %v", evs, asked)
	}
	if st := d.Stats(); st.AtRest != 1 || st.Scans != 0 {
		t.Fatalf("stats %+v", st)
	}
	// The verdict is cached in memory: the store isn't asked again.
	d.DecideNetworkTaint(context.Background(), Request{File: f, Path: f.Name(), Proc: chromeProc, Ident: ident, At: at.Add(time.Hour)})
	if len(asked) != 1 {
		t.Fatalf("asked again: %v", asked)
	}
}

func TestParseUSNRecords(t *testing.T) {
	rec := func(major uint16, ref [16]byte, reason, attrs uint32) []byte {
		var b []byte
		switch major {
		case 2:
			b = make([]byte, 64)
			copy(b[8:16], ref[:8])
			binary.LittleEndian.PutUint32(b[40:], reason)
			binary.LittleEndian.PutUint32(b[52:], attrs)
		case 3:
			b = make([]byte, 80)
			copy(b[8:24], ref[:])
			binary.LittleEndian.PutUint32(b[56:], reason)
			binary.LittleEndian.PutUint32(b[68:], attrs)
		default:
			b = make([]byte, 40)
		}
		binary.LittleEndian.PutUint32(b[0:], uint32(len(b))) // #nosec G115 -- test record length
		binary.LittleEndian.PutUint16(b[4:], major)
		return b
	}
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, 4242)
	buf = append(buf, rec(2, [16]byte{1}, usnReasonDataExtend|usnReasonClose, 0)...)
	buf = append(buf, rec(2, [16]byte{2}, usnReasonFileCreate|usnReasonClose, fileAttributeDirectory)...)   // a folder
	buf = append(buf, rec(2, [16]byte{3}, usnReasonDataOverwrite|usnReasonFileDelete|usnReasonClose, 0)...) // deleted
	buf = append(buf, rec(4, [16]byte{4}, 0, 0)...)                                                         // range record: skipped
	buf = append(buf, rec(3, [16]byte{5, 0, 0, 0, 0, 0, 0, 0, 9}, usnReasonRenameNewName|usnReasonClose, 0)...)
	buf = append(buf, rec(2, [16]byte{6}, usnReasonClose, 0)...) // closed, nothing written
	buf = append(buf, 0xFF, 0xFF, 0xFF)                          // a truncated record ends the parse

	next, changes := parseUSNRecords(buf)
	if next != 4242 || len(changes) != 2 || changes[0].ref != [16]byte{1} || changes[1].ref != [16]byte{5, 0, 0, 0, 0, 0, 0, 0, 9} {
		t.Fatalf("next %d changes %+v", next, changes)
	}
	if n, c := parseUSNRecords([]byte{1, 2}); n != 0 || c != nil {
		t.Fatalf("short buffer: %d %v", n, c)
	}
}
