package policy

import "testing"

// forceMonitor is what the read-only build applies to every bundle (#547);
// it is tested here in every build.
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
	forceMonitor(b)
	for _, p := range b.Policies[:4] {
		if p.Action != ActionMonitor {
			t.Errorf("policy %s: %q, want monitor", p.ID, p.Action)
		}
	}
	if b.Policies[4].Action != "explode" {
		t.Error("an unknown action must stay, so Compile still rejects it")
	}
	if f.AuditOnly == nil || !*f.AuditOnly || f.Uploads.Inspection.Enabled || f.NetworkControl.Enabled || f.AtRest.Enabled {
		t.Errorf("files module still enforces: %+v", *f)
	}
	if off {
		t.Error("forceMonitor changed the caller's audit_only value instead of replacing the pointer")
	}

	// Applying it again writes nothing: the same pointer stays.
	ptr := f.AuditOnly
	forceMonitor(b)
	if f.AuditOnly != ptr {
		t.Error("a second pass replaced audit_only")
	}
}
