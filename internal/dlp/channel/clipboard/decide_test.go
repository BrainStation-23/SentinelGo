package clipboard

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
)

func compile(t *testing.T, policies string) *policy.Compiled {
	t.Helper()
	b, err := policy.Decode(fmt.Appendf(nil, `{"schema_version":1,"version":"v7","enabled":true,"evidence_mode":"masked",
		"modules":{"clipboard":{"enabled":true,"block_message":"Blocked by SentinelOps: {{detector}}"}},
		"policies":[%s]}`, policies))
	if err != nil {
		t.Fatal(err)
	}
	c := policy.Compile(b)
	if len(c.CompileErrors) > 0 {
		t.Fatalf("compile errors: %+v", c.CompileErrors)
	}
	return c
}

const (
	blockCards = `{"id":"p-block","name":"Block cards","severity":"high","channels":["clipboard"],"action":"block","match":"any",
		"detectors":[{"id":"pii.credit_card","rule_id":"r1","min_count":1}],"exceptions":{"source_apps":["KeePassXC"]}}`
	monitorFalcon = `{"id":"p-mon","name":"Falcon","severity":"low","channels":["clipboard"],"action":"monitor","match":"any",
		"detectors":[{"id":"custom.keywords","rule_id":"r2","keywords":["falcon"]}]}`
)

var now = time.Unix(1_700_000_000, 0)

func TestDecide_Block(t *testing.T) {
	p := compile(t, blockCards+","+monitorFalcon)
	text := "pay with 4111 1111 1111 1111 for project falcon"
	d := Decide(p, text, events.SourceApp{Name: "chrome.exe"}, now)
	if !d.Block || d.Message != "Blocked by SentinelOps: credit card" {
		t.Fatalf("decision = %+v", d)
	}
	if len(d.Events) != 2 {
		t.Fatalf("events = %d, want one per matching policy", len(d.Events))
	}
	for _, ev := range d.Events {
		if ev.Action != events.ActionBlocked || ev.Channel != "clipboard" || ev.PolicyVersion != "v7" || ev.SourceApp.Name != "chrome.exe" {
			t.Errorf("event = %+v", ev)
		}
		if strings.Contains(fmt.Sprintf("%+v", ev), "4111 1111 1111 1111") {
			t.Error("event carries the card number")
		}
	}
}

func TestDecide_MonitorOnly(t *testing.T) {
	p := compile(t, blockCards+","+monitorFalcon)
	d := Decide(p, "project falcon kickoff", events.SourceApp{}, now)
	if d.Block || len(d.Events) != 1 || d.Events[0].Action != events.ActionMonitored || d.Events[0].Severity != "low" {
		t.Errorf("decision = %+v", d)
	}
}

func TestDecide_SourceAppException(t *testing.T) {
	p := compile(t, blockCards)
	for _, src := range []events.SourceApp{
		{Name: "KeePassXC.exe"},
		{Path: `C:\Program Files\KeePassXC\keepassxc.exe`},
		{BundleID: "keepassxc"},
	} {
		if d := Decide(p, "4111111111111111", src, now); d.Block || len(d.Events) > 0 {
			t.Errorf("source %+v not exempted: %+v", src, d)
		}
	}
}

func TestDecide_NothingToDo(t *testing.T) {
	p := compile(t, blockCards)
	if d := Decide(p, "hello world", events.SourceApp{}, now); d.Block || len(d.Events) > 0 {
		t.Errorf("clean text: %+v", d)
	}
	if d := Decide(nil, "4111111111111111", events.SourceApp{}, now); d.Block {
		t.Error("nil policy blocked")
	}
	usbOnly := compile(t, strings.Replace(blockCards, `["clipboard"]`, `["usb"]`, 1))
	if d := Decide(usbOnly, "4111111111111111", events.SourceApp{}, now); d.Block {
		t.Error("usb-only policy applied to the clipboard")
	}
}

func TestDetectorName(t *testing.T) {
	for id, want := range map[string]string{
		"secrets.aws-access-token": "aws access token",
		"pii.credit_card":          "credit card",
		"custom.regex":             "restricted content",
	} {
		if got := DetectorName(id); got != want {
			t.Errorf("DetectorName(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestDecide_ExceptionPathEitherSeparator(t *testing.T) {
	p := compile(t, strings.Replace(blockCards, `["KeePassXC"]`, `["C:/Program Files/KeePassXC/KeePassXC.exe"]`, 1))
	src := events.SourceApp{Path: `C:\Program Files\KeePassXC\keepassxc.exe`}
	if d := Decide(p, "4111111111111111", src, now); d.Block {
		t.Error("forward-slash exemption didn't match a backslash path")
	}
}

// The same text from another app is a new copy (an exempt app's copy must
// not let a protected app's copy through).
func TestDedupeKey_IncludesSource(t *testing.T) {
	a := dedupeKey("secret", events.SourceApp{Name: "keepassxc.exe"})
	b := dedupeKey("secret", events.SourceApp{Name: "slack.exe"})
	if a == b {
		t.Error("same key for different source apps")
	}
	if a != dedupeKey("secret", events.SourceApp{Name: "keepassxc.exe"}) {
		t.Error("key not stable")
	}
}

func TestMarkMonitored(t *testing.T) {
	evs := []events.Event{{Action: events.ActionBlocked}, {Action: events.ActionBlocked}}
	markMonitored(evs)
	for _, ev := range evs {
		if ev.Action != events.ActionMonitored {
			t.Errorf("action = %s", ev.Action)
		}
	}
}
