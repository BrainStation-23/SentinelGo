package packages

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type fakeEnqueuer struct {
	uploads []Upload
	err     error
	failAt  int // 1-based call that fails; 0 = never
}

func (f *fakeEnqueuer) Enqueue(_ context.Context, u Upload) error {
	if f.failAt > 0 && len(f.uploads)+1 == f.failAt {
		return f.err
	}
	f.uploads = append(f.uploads, u)
	return nil
}

func manyPackages(n int, locLen int) []Package {
	out := make([]Package, n)
	loc := strings.Repeat("x", locLen)
	for i := range out {
		out[i] = Package{Ecosystem: EcosystemNPM, Name: fmt.Sprintf("p%d", i), Version: "1.0.0", Scope: ScopeProject, Location: loc}
	}
	return out
}

func TestSplitParts(t *testing.T) {
	if got := splitParts(nil); len(got) != 1 || len(got[0]) != 0 {
		t.Errorf("empty inventory = %d parts, want one empty part", len(got))
	}
	if got := splitParts(manyPackages(maxPartPackages+1, 10)); len(got) != 2 || len(got[0]) != maxPartPackages {
		t.Errorf("count split = %d parts (first %d)", len(got), len(got[0]))
	}
	// 1,000 rows with ~1 KB locations exceed the byte budget well before 5,000.
	parts := splitParts(manyPackages(1000, 1000))
	if len(parts) < 2 {
		t.Fatalf("byte split = %d parts, want several", len(parts))
	}
	total := 0
	for _, p := range parts {
		b, _ := json.Marshal(Upload{Snapshot: snapshotFull, Packages: p})
		if len(b) > 1<<20 {
			t.Errorf("part is %d bytes, over 1 MB", len(b))
		}
		total += len(p)
	}
	if total != 1000 {
		t.Errorf("parts hold %d packages, want 1000", total)
	}
}

func TestSend_FullMultiPart(t *testing.T) {
	e := &fakeEnqueuer{}
	now := time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)
	n, err := send(context.Background(), e, manyPackages(maxPartPackages*2+1, 5), true, now)
	if err != nil || n != 3 {
		t.Fatalf("send = %d, %v", n, err)
	}
	id := e.uploads[0].SnapshotID
	for i, u := range e.uploads {
		if u.Snapshot != snapshotFull || u.SnapshotID != id || u.Part != i+1 || u.Parts != 3 {
			t.Errorf("upload %d = %+v", i, u)
		}
		if u.CollectedAt != "2026-11-10T08:00:00Z" {
			t.Errorf("collected_at = %q", u.CollectedAt)
		}
	}
	if id == "" {
		t.Error("empty snapshot_id")
	}
}

func TestSend_OnePartOmitsPartFields(t *testing.T) {
	e := &fakeEnqueuer{}
	if _, err := send(context.Background(), e, manyPackages(3, 5), true, time.Now()); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(e.uploads[0])
	if strings.Contains(string(b), `"part"`) || !strings.Contains(string(b), `"snapshot_id"`) {
		t.Errorf("one-part upload = %s", b)
	}
}

func TestSend_IncompleteIsDelta(t *testing.T) {
	e := &fakeEnqueuer{}
	if _, err := send(context.Background(), e, manyPackages(3, 5), false, time.Now()); err != nil {
		t.Fatal(err)
	}
	u := e.uploads[0]
	if u.Snapshot != snapshotDelta || u.SnapshotID != "" || u.Parts != 0 {
		t.Errorf("incomplete upload = %+v", u)
	}
}

func TestSend_StopsOnError(t *testing.T) {
	boom := errors.New("boom")
	e := &fakeEnqueuer{failAt: 2, err: boom}
	n, err := send(context.Background(), e, manyPackages(maxPartPackages*3, 5), true, time.Now())
	if !errors.Is(err, boom) || n != 1 || len(e.uploads) != 1 {
		t.Errorf("send = %d, %v (%d uploads)", n, err, len(e.uploads))
	}
}
