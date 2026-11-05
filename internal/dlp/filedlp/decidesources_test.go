package filedlp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sentinelgo/internal/dlp/detect"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/filescan"
)

// A file being created on a USB stick is judged before anything is written,
// by the file its writer has open: blocked when that file matches a block
// policy and the module enforces; otherwise allowed and not recorded (the
// after-write path records it on close).
func TestDecider_DecideBySources(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"cards.csv", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	opener := func(src SourceRef) (*os.File, Identity, error) {
		f, err := os.Open(filepath.Join(dir, filepath.Base(src.Path)))
		return f, Identity{Dev: 1, Ino: src.Ino, Size: 10}, err
	}
	sensitive := filescan.Result{Status: filescan.StatusScanned, SHA256: strings.Repeat("ab", 32), Findings: []detect.Finding{cardFinding()}}
	scanner := byNameScanner{res: map[string]filescan.Result{"cards.csv": sensitive, "notes.txt": {Status: filescan.StatusScanned}}}
	cards := SourceRef{Path: "/home/alice/cards.csv", Ino: 1}
	notes := SourceRef{Path: "/home/alice/notes.txt", Ino: 2}

	run := func(bundle string, sources ...SourceRef) (Verdict, []events.Event) {
		sink := &recordingSink{}
		d := NewDecider(scanner, sink)
		d.SetSourceOpener(opener)
		d.Apply(compile(t, bundle))
		r := usbRequest()
		r.Ident.Size = 0 // just created
		r.Sources = sources
		return d.DecideBySources(context.Background(), r, MethodOpenFile), sink.events()
	}

	v, evs := run(taintBundle("block", ""), notes, cards)
	if !v.Block || len(evs) != 1 || evs[0].Action != events.ActionBlocked || evs[0].Correlation == nil ||
		evs[0].Correlation.Method != MethodOpenFile || evs[0].Correlation.SourceSHA256 != sensitive.SHA256 {
		t.Fatalf("block: %+v %+v", v, evs)
	}
	if v, evs := run(taintBundle("block", ""), notes); v.Block || len(evs) != 0 {
		t.Errorf("clean source: %+v %+v", v, evs)
	}
	if v, evs := run(taintBundle("monitor", ""), cards); v.Block || len(evs) != 0 {
		t.Errorf("monitor policy: %+v %+v", v, evs)
	}
	audit := strings.Replace(taintBundle("block", ""), `"audit_only": false`, `"audit_only": true`, 1)
	if v, evs := run(audit, cards); v.Block || len(evs) != 0 {
		t.Errorf("audit only: %+v %+v", v, evs)
	}
	if v, _ := run(taintBundle("block", "")); v.Block {
		t.Error("blocked without sources")
	}
}
