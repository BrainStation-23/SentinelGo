//go:build readonly

package policy

import "testing"

// The read-only build reports every match as monitored and never blocks,
// whatever the bundle asks (#547).
func TestReadOnly_MonitorOnly(t *testing.T) {
	b, err := Decode([]byte(`{
	  "schema_version": 1, "version": "v1", "enabled": true,
	  "modules": {
	    "clipboard": {"enabled": true},
	    "files": {"enabled": true, "audit_only": false, "channels": {"file.upload": true},
	      "uploads": {"inspection": {"enabled": true, "intercept": ["example.com"]}},
	      "network_control": {"enabled": true},
	      "at_rest": {"enabled": true}}},
	  "policies": [
	    {"id": "b", "channels": ["clipboard"], "action": "block", "detectors": [{"id": "pii.email", "rule_id": "r1"}]},
	    {"id": "w", "channels": ["clipboard"], "action": "warn", "detectors": [{"id": "pii.email", "rule_id": "r2"}]},
	    {"id": "o", "channels": ["file.upload"], "action": "block_override", "detectors": [{"id": "pii.email", "rule_id": "r3"}]},
	    {"id": "x", "channels": ["clipboard"], "action": "explode", "detectors": [{"id": "pii.email", "rule_id": "r4"}]}
	  ]}`))
	if err != nil {
		t.Fatal(err)
	}
	c := Compile(b)
	for _, p := range c.Policies {
		if p.Action != ActionMonitor || p.Blocks() {
			t.Errorf("policy %s: action %q, blocks %v", p.ID, p.Action, p.Blocks())
		}
	}
	if len(c.Policies) != 3 || len(c.CompileErrors) == 0 {
		t.Errorf("an unknown action must still be rejected: %d policies, errors %v", len(c.Policies), c.CompileErrors)
	}
	f := c.Modules.Files
	if !f.IsAuditOnly() || f.InspectsUploads() || f.NetworkControl.Enabled || f.AtRest.Enabled {
		t.Errorf("files module still enforces: %+v", f)
	}

	// A bundle built in code is made monitor-only by Compile too.
	off := false
	raw := &Bundle{Version: "v2", Policies: []Policy{{ID: "b", Action: ActionBlock, Channels: []string{ChannelClipboard}}}}
	raw.Modules.Files.AuditOnly = &off
	if c := Compile(raw); c.Policies[0].Action != ActionMonitor || !c.Modules.Files.IsAuditOnly() {
		t.Errorf("Compile kept %q, audit-only %v", c.Policies[0].Action, c.Modules.Files.IsAuditOnly())
	}
	// And a nil audit_only reads as audit-only whatever it says.
	f.AuditOnly = &off
	if !f.IsAuditOnly() {
		t.Error("IsAuditOnly false in the read-only build")
	}
}
