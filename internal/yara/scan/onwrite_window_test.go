package scan

import (
	"path/filepath"
	"testing"

	"sentinelgo/internal/yara"
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
