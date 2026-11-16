package scan

import (
	"testing"
	"time"

	"sentinelgo/internal/yara"
)

func (q *fakeQueue) progress() []*yara.ScanProgress {
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []*yara.ScanProgress
	for _, ev := range q.evs {
		if ev.Progress != nil {
			out = append(out, ev.Progress)
		}
	}
	return out
}

// With the bundle's scan_progress, a running scan sends its counts at most
// once per interval (#498); without it, never.
func TestProgress_SentPerInterval(t *testing.T) {
	dir := files(t, "a.txt", "bad.txt", "c.txt")
	a := bundle(customSchedule(dir))
	a.Bundle.ScanProgress = &yara.ScanProgressConfig{IntervalSeconds: 120}
	sc := &fakeScanner{gate: make(chan struct{}), entered: make(chan struct{}, 10)}
	g := newRig(t, a, sc)
	if err := g.r.Tick(); err != nil {
		t.Fatal(err)
	}
	<-sc.entered // a.txt, at the start: nothing due
	g.advance(3 * time.Minute)
	sc.gate <- struct{}{}
	<-sc.entered // bad.txt: one interval passed
	g.advance(30 * time.Second)
	sc.gate <- struct{}{}
	<-sc.entered // c.txt: not due again yet
	sc.gate <- struct{}{}
	s := g.waitEnd(t)
	ps := g.q.progress()
	if len(ps) != 1 {
		t.Fatalf("%d progress events", len(ps))
	}
	p := ps[0]
	want := yara.ScanProgress{ScanID: s.ScanID, Trigger: yara.TriggerScheduled, Preset: yara.PresetCustom,
		FilesScanned: 1, RootIndex: 0, RootsTotal: 1, ElapsedSeconds: 180}
	if *p != want {
		t.Fatalf("progress %+v, want %+v", *p, want)
	}
}

func TestProgress_NotWithoutBundleBlock(t *testing.T) {
	dir := files(t, "a.txt")
	g := newRig(t, bundle(), &fakeScanner{})
	g.advance(time.Hour)
	if _, err := g.r.StartOnDemand(yara.TaskParams{Preset: yara.PresetCustom, Paths: []string{dir}}); err != nil {
		t.Fatal(err)
	}
	g.waitEnd(t)
	if n := len(g.q.progress()); n != 0 {
		t.Fatalf("%d progress events from a server that doesn't take them", n)
	}
}
