package filedlp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/dlp/detect"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/filescan"
)

func overrideBundle(extra string) string {
	return `{"schema_version": 1, "version": "v1", "enabled": true, "evidence_mode": "masked",
	  "modules": {"files": {"enabled": true, "channels": {"file.removable": true}, "audit_only": false` + extra + `}},
	  "policies": [{"id": "p1", "name": "Cards", "channels": ["file.removable"], "action": "block_override",
	    "detectors": [{"id": "pii.credit_card", "rule_id": "r1", "min_count": 1}]}]}`
}

func overrideDecider(t *testing.T, bundle string) (*Decider, *recordingSink) {
	t.Helper()
	sink := &recordingSink{}
	d := NewDecider(&fakeScanner{res: filescan.Result{Status: filescan.StatusScanned, SHA256: "aa11",
		Findings: []detect.Finding{cardFinding()}}}, sink)
	d.Apply(compile(t, bundle))
	return d, sink
}

// A block_override block can be overridden once by its own user, with a
// reason: an overridden event is recorded and the same file then passes.
func TestOverride_Flow(t *testing.T) {
	d, sink := overrideDecider(t, overrideBundle(""))
	r := usbRequest()
	r.Proc.UID = "1000"
	v := d.Decide(context.Background(), r, true)
	if !v.Block || !v.Overridable || v.EventID == "" {
		t.Fatalf("verdict %+v", v)
	}
	if err := d.Override(v.EventID, "1001", "need it"); !errors.Is(err, ErrOverrideUnknown) {
		t.Fatalf("another user: %v", err)
	}
	if err := d.Override(v.EventID, "1000", "   "); !errors.Is(err, ErrOverrideReason) {
		t.Fatalf("empty reason: %v", err)
	}
	if err := d.Override(v.EventID, "1000", strings.Repeat("x", 1001)); !errors.Is(err, ErrOverrideReason) {
		t.Fatalf("long reason: %v", err)
	}
	if err := d.Override(v.EventID, "1000", "Customer asked for the export"); err != nil {
		t.Fatal(err)
	}
	evs := sink.events()
	last := evs[len(evs)-1]
	if last.Action != events.ActionOverridden || last.Override == nil || last.Override.Justification != "Customer asked for the export" ||
		last.EventID == v.EventID {
		t.Fatalf("overridden event %+v", last)
	}
	if err := d.Override(v.EventID, "1000", "again"); !errors.Is(err, ErrOverrideUnknown) {
		t.Fatalf("second override of one block: %v", err)
	}
	// the retry passes, and isn't recorded again as blocked
	before := len(sink.events())
	if v := d.Decide(context.Background(), r, true); v.Block {
		t.Fatalf("retry blocked: %+v", v)
	}
	if evs := sink.events()[before:]; len(evs) != 1 || evs[0].Action == events.ActionBlocked {
		t.Fatalf("retry events %+v", evs)
	}
	// another user copying the same file is still blocked
	r2 := r
	r2.Proc.UID = "1001"
	if v := d.Decide(context.Background(), r2, true); !v.Block {
		t.Fatal("override leaked to another user")
	}
}

func TestOverride_DailyLimit(t *testing.T) {
	d, _ := overrideDecider(t, overrideBundle(`, "override_daily_limit": 1`))
	r := usbRequest()
	r.Proc.UID = "1000"
	v1 := d.Decide(context.Background(), r, true)
	if err := d.Override(v1.EventID, "1000", "one"); err != nil {
		t.Fatal(err)
	}
	r.Ident.Ino++ // another file version, another block
	d.overrides.mu.Lock()
	d.overrides.grants = map[string]time.Time{}
	d.overrides.mu.Unlock()
	v2 := d.Decide(context.Background(), r, true)
	if !v2.Block {
		t.Fatal("not blocked")
	}
	if err := d.Override(v2.EventID, "1000", "two"); !errors.Is(err, ErrOverrideLimit) {
		t.Fatalf("over the limit: %v", err)
	}
	// limit 0: overrides off, a plain block
	d0, _ := overrideDecider(t, overrideBundle(`, "override_daily_limit": 0`))
	if v := d0.Decide(context.Background(), r, true); !v.Block || v.Overridable {
		t.Fatalf("limit 0: %+v", v)
	}
}

// An approved exception lets a file through on both paths.
func TestExceptions_Release(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	for _, tc := range []struct {
		ex    string
		block bool
	}{
		{`{"id": "x", "policy_id": "p1", "channel": "file.removable", "sha256": "AA11", "expires_at": "` + exp + `"}`, false},
		{`{"id": "x", "policy_id": "p1", "channel": "file.removable", "user": "alice", "expires_at": "` + exp + `"}`, false},
		{`{"id": "x", "policy_id": "p1", "channel": "file.removable", "user": "bob", "expires_at": "` + exp + `"}`, true},
		{`{"id": "x", "policy_id": "p1", "channel": "file.removable", "expires_at": "2020-01-01T00:00:00Z"}`, true},
		{`{"id": "x", "policy_id": "other", "channel": "file.removable", "expires_at": "` + exp + `"}`, true},
	} {
		d, _ := overrideDecider(t, strings.Replace(overrideBundle(`, "exceptions": [`+tc.ex+`]`), `"block_override"`, `"block"`, 1))
		r := usbRequest()
		if v := d.Decide(context.Background(), r, true); v.Block != tc.block {
			t.Errorf("%s: block %v", tc.ex, v.Block)
		}
	}
}
