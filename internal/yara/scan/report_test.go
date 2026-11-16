package scan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"sentinelgo/internal/yara"
	"sentinelgo/internal/yara/walk"
)

func sum64(m map[string]int64) int64 {
	var n int64
	for _, v := range m {
		n += v
	}
	return n
}

// The v1.2 report (#497): reasons that add up to the totals, problem files
// (errors first), what was read, and the scope.
func TestReport_BreakdownScopeAndProblems(t *testing.T) {
	dir := files(t, "a.txt", "bad.bin", "locked.txt")
	if err := os.WriteFile(filepath.Join(dir, "big.iso"), make([]byte, 2<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	g := newRig(t, bundle(), &fakeScanner{unread: "locked.txt"})
	if _, err := g.r.StartOnDemand(yara.TaskParams{Preset: yara.PresetCustom, Paths: []string{dir}}); err != nil {
		t.Fatal(err)
	}
	s := g.waitEnd(t)
	if s.State != yara.ScanCompleted || s.EndReason != "" || s.FilesScanned != 2 || s.Errors != 1 || s.FilesSkipped != 1 {
		t.Fatalf("summary %+v", s)
	}
	if s.SkippedByReason[walk.SkipTooLarge] != 1 || sum64(s.SkippedByReason) != s.FilesSkipped {
		t.Errorf("skipped_by_reason %v, files_skipped %d", s.SkippedByReason, s.FilesSkipped)
	}
	if s.ErrorsByReason[yara.ErrRead] != 1 || sum64(s.ErrorsByReason) != s.Errors {
		t.Errorf("errors_by_reason %v, errors %d", s.ErrorsByReason, s.Errors)
	}
	if len(s.ProblemFiles) != 2 {
		t.Fatalf("problem files %+v", s.ProblemFiles)
	}
	first, second := s.ProblemFiles[0], s.ProblemFiles[1]
	if first.Reason != yara.ErrRead || first.Path == nil || filepath.Base(*first.Path) != "locked.txt" {
		t.Errorf("first problem (errors first) %+v", first)
	}
	if second.Reason != walk.SkipTooLarge || second.Size != 2<<20 || second.Path == nil || filepath.Base(*second.Path) != "big.iso" {
		t.Errorf("second problem %+v", second)
	}
	if s.BytesScanned == 0 {
		t.Error("bytes_scanned not counted")
	}
	sc := s.Scope
	if sc == nil || len(sc.Roots) != 1 || sc.Roots[0] != dir || len(sc.Rulesets) != 1 ||
		sc.Rulesets[0] != (yara.ScopeRuleset{ID: rsA, Revision: 4}) || sc.Limits.MaxFileBytes != 1<<20 {
		t.Fatalf("scope %+v", sc)
	}
	// The status's last scan keeps the counts, not the paths.
	if ls := g.r.LastScan().Brief(); ls.Scope != nil || ls.ProblemFiles != nil || ls.ErrorsByReason == nil {
		t.Errorf("brief last scan %+v", ls)
	}
}

// Hashed path mode hashes the scope's folders and problem-file paths.
func TestReport_HashedScopeAndProblems(t *testing.T) {
	dir := files(t, "locked.txt")
	a := bundle()
	a.Bundle.Evidence = yara.Evidence{PathMode: yara.PathModeHashed}
	g := newRig(t, a, &fakeScanner{unread: "locked.txt"})
	if _, err := g.r.StartOnDemand(yara.TaskParams{Preset: yara.PresetCustom, Paths: []string{dir}}); err != nil {
		t.Fatal(err)
	}
	s := g.waitEnd(t)
	if len(s.ProblemFiles) != 1 || s.ProblemFiles[0].Path != nil || s.ProblemFiles[0].PathHash == nil || s.ProblemFiles[0].FileExt != "txt" {
		t.Fatalf("problem files %+v", s.ProblemFiles)
	}
	if s.Scope == nil || len(s.Scope.Roots) != 1 || !yara.IsSHA256(s.Scope.Roots[0]) {
		t.Fatalf("scope %+v", s.Scope)
	}
}

// Why a scan stopped: file limit, threat hunting turned off, workers down.
func TestReport_EndReasons(t *testing.T) {
	t.Run("file_limit", func(t *testing.T) {
		dir := files(t, "a.txt", "b.txt", "c.txt")
		a := bundle(customSchedule(dir))
		a.Bundle.Limits.MaxFilesPerScan = 1
		g := newRig(t, a, &fakeScanner{})
		if err := g.r.Tick(); err != nil {
			t.Fatal(err)
		}
		if s := g.waitEnd(t); s.State != yara.ScanPartial || s.EndReason != yara.EndFileLimit {
			t.Fatalf("summary %+v", s)
		}
	})
	t.Run("disabled", func(t *testing.T) {
		dir := files(t, "a.txt")
		sc := &fakeScanner{gate: make(chan struct{}), entered: make(chan struct{}, 1)}
		g := newRig(t, bundle(customSchedule(dir)), sc)
		if err := g.r.Tick(); err != nil {
			t.Fatal(err)
		}
		<-sc.entered
		g.r.Disable()
		if s := g.waitEnd(t); s.State != yara.ScanCancelled || s.EndReason != yara.EndDisabled {
			t.Fatalf("summary %+v", s)
		}
	})
	t.Run("worker_failure", func(t *testing.T) {
		names := make([]string, maxWorkerFailures+2)
		for i := range names {
			names[i] = string(rune('a'+i)) + ".txt"
		}
		g := newRig(t, bundle(), failingScanner{})
		if _, err := g.r.StartOnDemand(yara.TaskParams{Preset: yara.PresetCustom, Paths: []string{files(t, names...)}}); err != nil {
			t.Fatal(err)
		}
		s := g.waitEnd(t)
		if s.EndReason != yara.EndWorkerFailure || s.ErrorsByReason[yara.ErrWorkerFailed] != s.Errors {
			t.Fatalf("summary %+v", s)
		}
	})
}

func TestEndReason(t *testing.T) {
	th := &walk.Throttle{Limit: yara.EndTimeLimit}
	for _, c := range []struct {
		err, cause error
		want       string
	}{
		{nil, nil, ""},
		{walk.ErrPartial, nil, yara.EndTimeLimit},
		{errWorkers, nil, yara.EndWorkerFailure},
		{errNoRules, nil, yara.EndNoRules},
		{context.Canceled, errCancelled, yara.EndCancelled},
		{context.Canceled, errDisabled, yara.EndDisabled},
		{context.Canceled, errShutdown, yara.EndShutdown},
		{errors.New("disk full"), nil, yara.EndError},
	} {
		if got := endReason(c.err, c.cause, th); got != c.want {
			t.Errorf("endReason(%v, %v) = %q, want %q", c.err, c.cause, got, c.want)
		}
	}
}
