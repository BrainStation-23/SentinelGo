package scan

import (
	"os"
	"path/filepath"
	"testing"

	"sentinelgo/internal/yara"
	"sentinelgo/internal/yara/walk"
)

func owProblem(path string) func(w *owWindow) {
	return func(w *owWindow) {
		w.errors++
		w.rep.Fail(yara.ErrList, 1)
		w.rep.Problem(path, yara.ErrList, "access denied", 0, true)
	}
}

func (g *owRig) cfg() *owConfig {
	g.ow.mu.Lock()
	defer g.ow.mu.Unlock()
	return g.ow.cfg
}

// A window belongs to the bundle that opened it. Switching from full to
// hashed paths: a file from a scan that began under the old bundle never
// reopens an old full-path window, and a file under the new bundle never
// lands in one, so no plain path reaches a hashed-mode summary.
func TestOnWrite_WindowBoundToBundle(t *testing.T) {
	dir := files(t, "a.txt")
	full := onWriteBundle(dir)
	g := newOWRig(t, full, &fakeScanner{}, OnWriteOptions{})
	g.ow.Apply(full)
	oldCfg := g.cfg()
	g.ow.count(oldCfg, owProblem(filepath.Join(dir, "old-1.txt")))

	hashed := onWriteBundle(dir)
	hashed.Bundle.Evidence.PathMode = yara.PathModeHashed

	// Apply swaps the configuration before it closes the window: a file
	// counted in between ends the old window and opens a hashed one.
	newCfg := g.ow.config(hashed)
	g.ow.mu.Lock()
	g.ow.cfg = newCfg
	g.ow.mu.Unlock()
	secret := filepath.Join(dir, "new-secret.txt")
	g.ow.count(newCfg, owProblem(secret))

	// A scan that began under the old bundle finishes now: dropped.
	g.ow.count(oldCfg, owProblem(filepath.Join(dir, "old-2.txt")))

	g.ow.closeWindow()
	sums := g.q.summaries()
	if len(sums) != 2 {
		t.Fatalf("%d summaries, want the old window and the new one", len(sums))
	}
	old, cur := sums[0], sums[1]
	if len(old.ProblemFiles) != 1 || old.ProblemFiles[0].Path == nil || *old.ProblemFiles[0].Path != filepath.Join(dir, "old-1.txt") {
		t.Fatalf("old full-path window %+v", old.ProblemFiles)
	}
	if len(cur.ProblemFiles) != 1 || cur.ProblemFiles[0].Path != nil || cur.ProblemFiles[0].PathHash == nil {
		t.Fatalf("new window must hash the path: %+v", cur.ProblemFiles)
	}
	if old.ScanID == cur.ScanID {
		t.Error("the new bundle reused the old window")
	}

	// After Apply closed the windows, a stale completion opens nothing.
	g.ow.count(oldCfg, owProblem(filepath.Join(dir, "old-3.txt")))
	if st := g.ow.Status(); st != nil && st.Window != nil {
		t.Errorf("a stale scan reopened a window: %+v", st.Window)
	}
}

// A scan that began under the old bundle and found a match is dropped when
// it finishes after the bundle changed; it must not be cached as clean (or
// at all), or later scans would skip the file and never report the match.
func TestOnWrite_StaleMatchNotCached(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(bad, []byte("x "+marker+" x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sc := &fakeScanner{gate: make(chan struct{}), entered: make(chan struct{}, 10)}
	full := onWriteBundle(dir)
	g := newOWRig(t, full, sc, OnWriteOptions{})
	g.ow.Apply(full)
	oldCfg := g.cfg()

	done := make(chan struct{})
	go func() { defer close(done); g.ow.scan(bad) }()
	<-sc.entered // the old bundle's scan holds the file

	newer := onWriteBundle(dir)
	newer.Bundle.Version = "v2"
	newCfg := g.ow.config(newer)
	g.ow.mu.Lock()
	g.ow.cfg = newCfg
	g.ow.mu.Unlock()
	sc.gate <- struct{}{}
	<-done

	if m := g.q.matches(); len(m) != 0 {
		t.Fatalf("stale scan queued %d matches", len(m))
	}
	f, _, err := walk.Stat(oldCfg.walk, bad)
	if err != nil {
		t.Fatal(err)
	}
	if res, ok := g.ow.r.skipCache().Lookup(f.Key, oldCfg.rulesKey); ok {
		t.Errorf("dropped stale result cached as %v: later scans would skip the match", res)
	}
}
