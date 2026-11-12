package netctl

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

const taintOnly = `, "network_control": {"enabled": true, "taint_block": {"enabled": true, "minutes": 5},
  "allow_destinations": ["10.0.0.0/8"]}`

const chrome = `C:\Program Files\Google\Chrome\Application\chrome.exe`

// A taint block adds the app to the rules until it expires; a bundle with
// taint blocks only opens no firewall until something is tainted.
func TestController_TaintBlock(t *testing.T) {
	f := newFixture(t)
	now := time.Unix(2_000_000, 0)
	f.ctl.opts.Now = func() time.Time { return now }
	f.ctl.Apply(context.Background(), bundle(t, false, taintOnly))
	if open, _, _ := f.rules.state(); open || f.ctl.Status().State != StateActive {
		t.Fatalf("taint only, nothing tainted: open %v status %+v", open, f.ctl.Status())
	}
	f.ctl.TaintBlock(chrome, now.Add(5*time.Minute))
	open, _, r := f.rules.state()
	if !open || !reflect.DeepEqual(r.BlockApps, []string{chrome}) || len(r.Allow) != 1 {
		t.Fatalf("tainted: open %v rules %+v", open, r)
	}
	st := f.ctl.Status()
	if st.TaintBlocks.Active != 1 || st.TaintBlocks.LastStartedAt == nil || !st.TaintBlocks.LastStartedAt.Equal(now) {
		t.Errorf("status %+v", st.TaintBlocks)
	}
	// The same app again (in another case): still one block.
	f.ctl.TaintBlock(strings.ToUpper(chrome), now.Add(6*time.Minute))
	if _, _, r := f.rules.state(); len(r.BlockApps) != 1 {
		t.Errorf("duplicate taint: %q", r.BlockApps)
	}
	// Expired: lifted on the next sync.
	now = now.Add(7 * time.Minute)
	f.ctl.sync(context.Background())
	if open, _, _ := f.rules.state(); open || f.ctl.Status().TaintBlocks.Active != 0 {
		t.Errorf("expired: open %v status %+v", open, f.ctl.Status().TaintBlocks)
	}
}

// Taints are ignored in audit-only and dropped when taint blocks go off;
// blocked apps and taints share the rules.
func TestController_TaintBlockPolicy(t *testing.T) {
	f := newFixture(t)
	now := time.Unix(2_000_000, 0)
	f.ctl.opts.Now = func() time.Time { return now }
	f.ctl.Apply(context.Background(), bundle(t, true, taintOnly))
	f.ctl.TaintBlock(chrome, now.Add(time.Minute))
	if open, _, _ := f.rules.state(); open || f.ctl.Status().TaintBlocks.Active != 0 {
		t.Errorf("audit-only took a taint")
	}
	both := strings.Replace(controls, `"allow_destinations"`, `"taint_block": {"enabled": true}, "allow_destinations"`, 1)
	f.ctl.Apply(context.Background(), bundle(t, false, both))
	f.ctl.TaintBlock(chrome, now.Add(time.Minute))
	if _, _, r := f.rules.state(); len(r.BlockApps) != 3 {
		t.Errorf("blocked apps + taint: %q", r.BlockApps)
	}
	f.ctl.Apply(context.Background(), bundle(t, false, controls)) // taint blocks off
	if _, _, r := f.rules.state(); len(r.BlockApps) != 2 || f.ctl.Status().TaintBlocks.Active != 0 {
		t.Errorf("taints kept after taint blocks went off: %q", r.BlockApps)
	}
}

// The file hook's reason wins for the taint capability (its trace failed).
func TestWith_TaintCapability(t *testing.T) {
	f := newFixture(t)
	files := &fakeFiles{caps: map[string]string{CapTaintBlock: "unsupported:etw_unavailable"}}
	e := With(files, f.ctl)
	e.Apply(context.Background(), bundle(t, false, taintOnly))
	if got := e.Capabilities()[CapTaintBlock]; got != "unsupported:etw_unavailable" {
		t.Errorf("taint capability %q", got)
	}
	if got := e.Capabilities()[CapBlockedApps]; got != "supported" {
		t.Errorf("blocked apps capability %q", got)
	}
}
