package policy

import (
	"testing"
)

func TestCompiledChannelEnabled(t *testing.T) {
	c := Compile(&Bundle{Modules: Modules{Clipboard: ClipboardModule{Enabled: true}}})
	if !c.ChannelEnabled(ChannelClipboard) || !c.AnyChannelEnabled() {
		t.Error("clipboard module on, but channel reported off")
	}
	if c.ChannelEnabled("usb") {
		t.Error("unknown channel reported on")
	}

	off := Compile(&Bundle{})
	if off.ChannelEnabled(ChannelClipboard) || off.AnyChannelEnabled() {
		t.Error("clipboard module off, but channel reported on")
	}
}

func TestCompile_ContractExample(t *testing.T) {
	b, err := Decode([]byte(sampleBundle))
	if err != nil {
		t.Fatal(err)
	}
	c := Compile(b)
	if len(c.CompileErrors) != 0 {
		t.Fatalf("compile errors: %+v", c.CompileErrors)
	}
	if c.Clipboard == nil || len(c.For(ChannelClipboard)) != 1 {
		t.Fatalf("clipboard engine/policies missing: %+v", c)
	}
	res := c.Clipboard.Scan("this is CONFIDENTIAL")
	p := c.For(ChannelClipboard)[0]
	if ok, _ := c.Clipboard.Evaluate(p.Match, p.Rules, res); !ok {
		t.Error("keyword rule did not match")
	}
}

// One bad rule or policy is skipped and reported; everything else stays.
func TestCompile_BadRulesDontDisableOthers(t *testing.T) {
	b := &Bundle{
		SchemaVersion: 1, Version: "v",
		Modules: Modules{Clipboard: ClipboardModule{Enabled: true, MaxScanBytes: DefaultMaxScanBytes}},
		Policies: []Policy{
			{ID: "p-bad-action", Name: "x", Channels: []string{"clipboard"}, Action: "quarantine",
				Detectors: []Detector{{ID: "secrets.all", RuleID: "r0"}}},
			{ID: "p-bad-match", Name: "y", Channels: []string{"clipboard"}, Action: "monitor", Match: "most",
				Detectors: []Detector{{ID: "secrets.all", RuleID: "r00"}}},
			{ID: "p1", Name: "z", Channels: []string{"clipboard"}, Action: "monitor", Match: "all", Detectors: []Detector{
				{ID: "custom.regex", RuleID: "r-bad", Pattern: "missing closing ("},
				{ID: "pii.martian_id", RuleID: "r-unknown"},
				{ID: "custom.regex", RuleID: "r-good", Pattern: `falcon-\d+`},
			}},
			{ID: "p-usb", Name: "u", Channels: []string{"usb"}, Action: "monitor",
				Detectors: []Detector{{ID: "custom.regex", RuleID: "r-usb", Pattern: "zzz"}}},
		},
	}
	c := Compile(b)
	failed := map[string]bool{}
	for _, ce := range c.CompileErrors {
		failed[ce.RuleID] = true
	}
	for _, id := range []string{"p-bad-action", "p-bad-match", "r-bad", "r-unknown"} {
		if !failed[id] {
			t.Errorf("%s not reported; errors = %+v", id, c.CompileErrors)
		}
	}
	if failed["r-good"] {
		t.Error("good rule reported as failed")
	}
	clip := c.For(ChannelClipboard)
	if len(clip) != 1 || clip[0].ID != "p1" {
		t.Fatalf("clipboard policies = %+v, want only p1", clip)
	}
	res := c.Clipboard.Scan("falcon-1 zzz")
	if ok, _ := c.Clipboard.Evaluate(clip[0].Match, clip[0].Rules, res); !ok {
		t.Error("p1 (match all) disabled by its bad rules")
	}
	for _, f := range res.Findings {
		if f.RuleID == "r-usb" {
			t.Error("usb-only rule scanned on the clipboard")
		}
	}
}
