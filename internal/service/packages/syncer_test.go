package packages

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeSettings struct {
	settings Settings
	err      error
	calls    []string // known versions asked with
}

func (f *fakeSettings) FetchSettings(_ context.Context, known string) (Settings, bool, error) {
	f.calls = append(f.calls, known)
	if f.err != nil {
		return Settings{}, false, f.err
	}
	if known == f.settings.Version {
		return Settings{}, false, nil
	}
	return f.settings, true, nil
}

type harness struct {
	s        *Syncer
	settings *fakeSettings
	enq      *fakeEnqueuer
	collects int
	pkgs     []Package
	complete bool
	more     bool
	clock    time.Time
}

func newHarness(enabled bool) *harness {
	h := &harness{
		settings: &fakeSettings{settings: Settings{Version: "v1", Enabled: enabled, MaxDepth: 6}},
		enq:      &fakeEnqueuer{},
		pkgs:     manyPackages(3, 5),
		complete: true,
		clock:    time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC),
	}
	collect := func(context.Context, Settings) Collection {
		h.collects++
		return Collection{Packages: append([]Package(nil), h.pkgs...), Complete: h.complete, More: h.more}
	}
	h.s = NewSyncer(h.settings, h.enq, collect, nil)
	h.s.now = func() time.Time { return h.clock }
	h.s.nextCollect = h.clock.Add(time.Hour) // not due until settings change or time passes
	return h
}

func TestTick_DisabledCollectsNothing(t *testing.T) {
	h := newHarness(false)
	for range 3 {
		if err := h.s.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		h.clock = h.clock.Add(7 * time.Hour)
	}
	if h.collects != 0 || len(h.enq.uploads) != 0 {
		t.Errorf("disabled: %d collects, %d uploads", h.collects, len(h.enq.uploads))
	}
}

func TestTick_Schedule(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()

	// First tick: the settings are new, so it collects right away.
	if err := h.s.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if h.collects != 1 || len(h.enq.uploads) != 1 {
		t.Fatalf("first tick: %d collects, %d uploads", h.collects, len(h.enq.uploads))
	}
	if len(h.settings.calls) != 1 || h.settings.calls[0] != "" {
		t.Fatalf("first poll asked with %v, want one call with no known version", h.settings.calls)
	}

	// Next tick: same settings, not due.
	h.clock = h.clock.Add(TickInterval)
	_ = h.s.Tick(ctx)
	if h.collects != 1 {
		t.Errorf("not due but collected (%d)", h.collects)
	}
	if got := h.settings.calls[len(h.settings.calls)-1]; got != "v1" {
		t.Errorf("polled with known version %q, want v1", got)
	}

	// Due again, same inventory: collected, not uploaded.
	h.clock = h.clock.Add(collectInterval)
	_ = h.s.Tick(ctx)
	if h.collects != 2 || len(h.enq.uploads) != 1 {
		t.Errorf("unchanged: %d collects, %d uploads", h.collects, len(h.enq.uploads))
	}

	// A day after the last upload, unchanged is resent.
	h.clock = h.clock.Add(resendInterval)
	_ = h.s.Tick(ctx)
	if len(h.enq.uploads) != 2 {
		t.Errorf("resend: %d uploads, want 2", len(h.enq.uploads))
	}

	// Changed settings collect at once.
	h.settings.settings.Version = "v2"
	h.settings.settings.ProjectScan = true
	_ = h.s.Tick(ctx)
	if h.collects != 4 {
		t.Errorf("settings change: %d collects, want 4", h.collects)
	}
}

func TestTick_ChangedInventoryUploads(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()
	_ = h.s.Tick(ctx)
	h.pkgs = append(h.pkgs, Package{Ecosystem: EcosystemPyPI, Name: "new", Version: "1", Scope: ScopeGlobal, Location: "/x"})
	h.clock = h.clock.Add(collectInterval)
	_ = h.s.Tick(ctx)
	if len(h.enq.uploads) != 2 {
		t.Errorf("%d uploads, want 2", len(h.enq.uploads))
	}
}

func TestTick_IncompleteEmptySendsNothing(t *testing.T) {
	h := newHarness(true)
	h.pkgs, h.complete = nil, false
	_ = h.s.Tick(context.Background())
	if len(h.enq.uploads) != 0 {
		t.Errorf("incomplete empty inventory uploaded: %+v", h.enq.uploads)
	}
}

func TestTick_CompleteEmptySendsEmptyFullSnapshot(t *testing.T) {
	h := newHarness(true)
	h.pkgs = nil
	_ = h.s.Tick(context.Background())
	if len(h.enq.uploads) != 1 || h.enq.uploads[0].Snapshot != snapshotFull || len(h.enq.uploads[0].Packages) != 0 {
		t.Errorf("uploads = %+v", h.enq.uploads)
	}
}

func TestTick_SettingsErrorKeepsLastSettings(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()
	_ = h.s.Tick(ctx)

	h.settings.err = errors.New("offline")
	h.clock = h.clock.Add(collectInterval)
	h.pkgs = manyPackages(4, 5)
	err := h.s.Tick(ctx)
	if err == nil {
		t.Error("settings error not returned")
	}
	if h.collects != 2 || len(h.enq.uploads) != 2 {
		t.Errorf("last settings not used: %d collects, %d uploads", h.collects, len(h.enq.uploads))
	}
}

func TestTick_UploadErrorRetriesNextTime(t *testing.T) {
	h := newHarness(true)
	h.enq.failAt, h.enq.err = 1, errors.New("down")
	if err := h.s.Tick(context.Background()); err == nil {
		t.Fatal("upload error not returned")
	}
	h.enq.failAt = 0
	h.clock = h.clock.Add(collectInterval)
	_ = h.s.Tick(context.Background())
	if len(h.enq.uploads) != 1 {
		t.Errorf("not re-sent after a failed upload: %d uploads", len(h.enq.uploads))
	}
}

func TestSyncNow(t *testing.T) {
	h := newHarness(true)
	ctx := context.Background()
	if _, err := h.s.SyncNow(ctx); err != nil {
		t.Fatal(err)
	}
	res, err := h.s.SyncNow(ctx) // unchanged, but forced
	if err != nil || len(h.enq.uploads) != 2 || res.Packages != 3 || res.Parts != 1 || !res.Enabled || !res.Complete {
		t.Errorf("SyncNow = %+v, %v (%d uploads)", res, err, len(h.enq.uploads))
	}
}

func TestSyncNow_Disabled(t *testing.T) {
	h := newHarness(false)
	res, err := h.s.SyncNow(context.Background())
	if err != nil || res.Enabled || h.collects != 0 {
		t.Errorf("SyncNow = %+v, %v (%d collects)", res, err, h.collects)
	}
}

func TestSyncNow_NoSettingsYet(t *testing.T) {
	h := newHarness(true)
	h.settings.err = errors.New("offline")
	if _, err := h.s.SyncNow(context.Background()); err == nil {
		t.Error("SyncNow without any settings succeeded")
	}
}

func TestSyncNow_Busy(t *testing.T) {
	h := newHarness(true)
	release := make(chan struct{})
	entered := make(chan struct{})
	h.s.collect = func(context.Context, Settings) Collection {
		close(entered)
		<-release
		return Collection{Complete: true}
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = h.s.SyncNow(context.Background())
	}()
	<-entered
	_, err := h.s.SyncNow(context.Background())
	close(release)
	wg.Wait()
	if !errors.Is(err, ErrBusy) {
		t.Errorf("concurrent SyncNow = %v, want ErrBusy", err)
	}
}

func TestRetrierWrapsServerCalls(t *testing.T) {
	h := newHarness(true)
	calls := 0
	h.s.retry = func(_ context.Context, fn func() error) error {
		calls++
		return fn()
	}
	_ = h.s.Tick(context.Background())
	if calls != 2 { // settings poll + upload
		t.Errorf("retrier called %d times, want 2", calls)
	}
}

func TestRandDuration(t *testing.T) {
	for range 100 {
		if d := randDuration(time.Minute); d < 0 || d >= time.Minute {
			t.Fatalf("randDuration = %v", d)
		}
	}
	if randDuration(0) != 0 {
		t.Error("randDuration(0) != 0")
	}
}

func TestTick_UnfinishedProjectPassResumesSoon(t *testing.T) {
	h := newHarness(true)
	h.more = true
	_ = h.s.Tick(context.Background())
	h.clock = h.clock.Add(resumeInterval)
	_ = h.s.Tick(context.Background())
	if h.collects != 2 {
		t.Errorf("an unfinished pass waited for the next collection (%d collects)", h.collects)
	}
}
