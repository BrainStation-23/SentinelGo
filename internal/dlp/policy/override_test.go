package policy

import (
	"testing"
	"time"
)

// block_override (Compliance-OS#581) is a valid action that blocks; the
// files module carries the daily limit and the approved exceptions.
func TestBlockOverrideBundle(t *testing.T) {
	raw := []byte(`{"schema_version": 1, "version": "v1", "enabled": true,
	  "modules": {"files": {"enabled": true, "channels": {"file.removable": true},
	    "override_daily_limit": 3,
	    "exceptions": [{"id": "x1", "policy_id": "p1", "channel": "file.removable", "sha256": "AB", "user": "CORP\\alice", "expires_at": "2026-11-20T00:00:00Z"},
	                   {"id": "x2", "policy_id": "p1", "channel": "file.removable", "expires_at": "2026-11-20T00:00:00Z"}]}},
	  "policies": [{"id": "p1", "name": "Cards", "channels": ["file.removable", "clipboard"], "action": "block_override",
	    "detectors": [{"id": "pii.credit_card", "rule_id": "r1", "min_count": 1}]}]}`)
	b, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	c := Compile(b)
	if len(c.CompileErrors) > 0 {
		t.Fatalf("compile: %v", c.CompileErrors)
	}
	pols := c.For(ChannelFileRemovable)
	if len(pols) != 1 || !pols[0].Blocks() || pols[0].Action != ActionBlockOverride {
		t.Fatalf("policies %+v", pols)
	}
	f := c.Modules.Files
	if f.DailyOverrides() != 3 || len(f.Exceptions) != 2 {
		t.Fatalf("files %+v", f)
	}
	now := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	x1, x2 := f.Exceptions[0], f.Exceptions[1]
	for _, tc := range []struct {
		e    FileException
		pol  string
		ch   string
		sha  string
		user string
		at   time.Time
		want bool
	}{
		{x1, "p1", ChannelFileRemovable, "ab", `corp\alice`, now, true},
		{x1, "p1", ChannelFileRemovable, "cd", `CORP\alice`, now, false}, // another file
		{x1, "p1", ChannelFileRemovable, "ab", `CORP\bob`, now, false},   // another user
		{x1, "p2", ChannelFileRemovable, "ab", `CORP\alice`, now, false}, // another policy
		{x1, "p1", ChannelFileNetworkShare, "ab", `CORP\alice`, now, false},
		{x1, "p1", ChannelFileRemovable, "ab", `CORP\alice`, now.AddDate(0, 1, 0), false}, // expired
		{x2, "p1", ChannelFileRemovable, "anything", "anyone", now, true},
	} {
		if got := tc.e.Allows(tc.pol, tc.ch, tc.sha, tc.user, tc.at); got != tc.want {
			t.Errorf("%s %s %s %s %s: %v", tc.e.ID, tc.pol, tc.ch, tc.sha, tc.user, got)
		}
	}
}

func TestDailyOverrides(t *testing.T) {
	n := func(v int) *int { return &v }
	for _, tc := range []struct {
		v    *int
		want int
	}{{nil, 10}, {n(0), 0}, {n(-4), 0}, {n(5), 5}, {n(99999), 1000}} {
		m := FilesModule{OverrideDailyLimit: tc.v}
		if got := m.DailyOverrides(); got != tc.want {
			t.Errorf("%v: %d", tc.v, got)
		}
	}
}

func TestUnknownActionStillRejected(t *testing.T) {
	if err := validatePolicy(Policy{Name: "x", Action: "quarantine"}); err == nil {
		t.Fatal("unknown action accepted")
	}
	if err := validatePolicy(Policy{Name: "x", Action: ActionBlockOverride}); err != nil {
		t.Fatal(err)
	}
}
