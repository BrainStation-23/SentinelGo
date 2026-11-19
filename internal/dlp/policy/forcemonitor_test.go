package policy

import "testing"

// forceMonitor is what the read-only build applies when it compiles a bundle
// (#547); it is tested here in every build.
func TestForceMonitor(t *testing.T) {
	off := false
	b := &Bundle{Policies: []Policy{
		{ID: "b", Action: ActionBlock}, {ID: "w", Action: ActionWarn},
		{ID: "o", Action: ActionBlockOverride}, {ID: "m", Action: ActionMonitor},
		{ID: "x", Action: "explode"},
	}}
	f := &b.Modules.Files
	f.AuditOnly = &off
	f.Uploads.Inspection.Enabled = true
	f.NetworkControl.Enabled = true
	f.AtRest.Enabled = true
	got := forceMonitor(b)
	for _, p := range got.Policies[:4] {
		if p.Action != ActionMonitor {
			t.Errorf("policy %s: %q, want monitor", p.ID, p.Action)
		}
	}
	if got.Policies[4].Action != "explode" {
		t.Error("an unknown action must stay, so Compile still rejects it")
	}
	g := got.Modules.Files
	if g.AuditOnly == nil || !*g.AuditOnly || g.Uploads.Inspection.Enabled || g.NetworkControl.Enabled || g.AtRest.Enabled {
		t.Errorf("files module still enforces: %+v", g)
	}

	// The input, which the policy cache saves, keeps the server's policy.
	if b.Policies[0].Action != ActionBlock || off || !f.Uploads.Inspection.Enabled || !f.NetworkControl.Enabled || !f.AtRest.Enabled {
		t.Errorf("forceMonitor changed its input: %+v", b)
	}
}
