package security

import (
	"encoding/json"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

func boolPtrString(b *bool) string {
	if b == nil {
		return "nil"
	}
	if *b {
		return "true"
	}
	return "false"
}

func TestWindowsAutoRun(t *testing.T) {
	cases := []struct {
		name           string
		noDrive        int
		noAutorun      int
		users          []winAutoplayUser
		wantAutoRunOff string
		wantAutoPlay   string
	}{
		{"defaults, nobody signed in", -1, -1, nil, "false", "nil"},
		{"defaults, user with defaults", -1, -1, []winAutoplayUser{{-1, -1}}, "false", "false"},
		{"machine policy all drives and NoAutorun", 0xFF, 1, nil, "true", "true"},
		{"machine policy all drives without NoAutorun", 0xFF, -1, nil, "false", "true"},
		{"NoAutorun without all drives", 0x91, 1, nil, "false", "nil"},
		{"mask with extra bits still all drives", 0x1FF, 1, nil, "true", "true"},
		{"every user turned AutoPlay off in Settings", -1, -1, []winAutoplayUser{{-1, 1}, {-1, 1}}, "false", "true"},
		{"user policy turns AutoPlay off", 0x91, -1, []winAutoplayUser{{0xFF, 0}}, "false", "true"},
		{"one user still has AutoPlay", -1, -1, []winAutoplayUser{{-1, 1}, {-1, 0}}, "false", "false"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := windowsAutoRun(c.noDrive, c.noAutorun, c.users)
			if s := boolPtrString(got.AutoRunDisabled); s != c.wantAutoRunOff {
				t.Errorf("autorun_disabled = %s, want %s", s, c.wantAutoRunOff)
			}
			if s := boolPtrString(got.AutoPlayDisabled); s != c.wantAutoPlay {
				t.Errorf("autoplay_disabled = %s, want %s", s, c.wantAutoPlay)
			}
		})
	}
}

const appLockerEnforced = `<AppLockerPolicy Version="1"><RuleCollection Type="Appx" EnforcementMode="NotConfigured" />` +
	`<RuleCollection Type="Exe" EnforcementMode="Enabled"><FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="(Default Rule) All files located in the Program Files folder" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions></FilePathRule></RuleCollection>` +
	`<RuleCollection Type="Msi" EnforcementMode="AuditOnly"><FilePublisherRule Id="b7af7102-efde-4369-8a89-7a6a392d1473" Name="x" Description="" UserOrGroupSid="S-1-1-0" Action="Allow" /></RuleCollection></AppLockerPolicy>`

const appLockerAudit = "\xef\xbb\xbf" + `<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="AuditOnly"><FileHashRule Id="1" Name="x" Description="" UserOrGroupSid="S-1-1-0" Action="Allow" /></RuleCollection>` +
	`<RuleCollection Type="Script" EnforcementMode="Enabled"><RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions></RuleCollectionExtensions></RuleCollection></AppLockerPolicy>`

const appLockerEmpty = `<AppLockerPolicy Version="1"><RuleCollection Type="Appx" EnforcementMode="NotConfigured" /><RuleCollection Type="Exe" EnforcementMode="NotConfigured" /></AppLockerPolicy>`

func TestParseAppLockerPolicy(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		mode   string
		wantOK bool
	}{
		{"enforced collection with rules", appLockerEnforced, shared.AppControlEnforced, true},
		{"audit only; extensions are not rules", appLockerAudit, shared.AppControlAudit, true},
		{"no rules", appLockerEmpty, shared.AppControlOff, true},
		{"empty policy element", `<AppLockerPolicy Version="1" />`, shared.AppControlOff, true},
		{"not configured with rules enforces", `<AppLockerPolicy><RuleCollection Type="Dll" EnforcementMode="NotConfigured"><FilePathRule /></RuleCollection></AppLockerPolicy>`, shared.AppControlEnforced, true},
		{"empty output", "", "", false},
		{"not XML", "Get-AppLockerPolicy : error", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mode, ok := parseAppLockerPolicy(c.in)
			if mode != c.mode || ok != c.wantOK {
				t.Errorf("got (%q, %v), want (%q, %v)", mode, ok, c.mode, c.wantOK)
			}
		})
	}
}

func TestAppLockerControlNeedsAppIDSvc(t *testing.T) {
	if got := appLockerControl(shared.AppControlEnforced, true, false); got.Mode != shared.AppControlOff {
		t.Errorf("rules without AppIDSvc running must be off, got %q", got.Mode)
	}
	if got := appLockerControl(shared.AppControlEnforced, true, true); got.Mode != shared.AppControlEnforced {
		t.Errorf("got %q, want enforced", got.Mode)
	}
	if got := appLockerControl("", false, true); got != nil {
		t.Errorf("unreadable policy must be omitted, got %+v", got)
	}
}

func TestWdacControl(t *testing.T) {
	for in, want := range map[int]string{0: shared.AppControlOff, 1: shared.AppControlAudit, 2: shared.AppControlEnforced} {
		got := wdacControl(&in)
		if got == nil || got.Product != shared.AppControlWDAC || got.Mode != want {
			t.Errorf("wdacControl(%d) = %+v, want WDAC/%s", in, got, want)
		}
	}
	bad := 7
	if wdacControl(&bad) != nil || wdacControl(nil) != nil {
		t.Error("unknown or missing status must be omitted")
	}
}

func TestStrongestAppControl(t *testing.T) {
	ctl := func(p, m string) *shared.ApplicationControlInfo {
		return &shared.ApplicationControlInfo{Product: p, Mode: m}
	}
	cases := []struct {
		name string
		in   []*shared.ApplicationControlInfo
		want *shared.ApplicationControlInfo
	}{
		{"none readable", []*shared.ApplicationControlInfo{nil, nil}, nil},
		{"one", []*shared.ApplicationControlInfo{nil, ctl("AppLocker", "audit")}, ctl("AppLocker", "audit")},
		{"enforced beats audit", []*shared.ApplicationControlInfo{ctl("WDAC", "audit"), ctl("AppLocker", "enforced")}, ctl("AppLocker", "enforced")},
		{"tie keeps the first", []*shared.ApplicationControlInfo{ctl("WDAC", "off"), ctl("AppLocker", "off")}, ctl("WDAC", "off")},
		{"unknown mode skipped", []*shared.ApplicationControlInfo{ctl("WDAC", "weird")}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := strongestAppControl(c.in...)
			if (got == nil) != (c.want == nil) || (got != nil && *got != *c.want) {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestGatekeeperControl(t *testing.T) {
	cases := []struct {
		in   string
		want string // "" = omitted
	}{
		{"assessments enabled\n", shared.AppControlEnforced},
		{"assessments disabled\n", shared.AppControlOff},
		{"some warning\nassessments enabled", shared.AppControlEnforced},
		{"", ""},
		{"spctl: command not found", ""},
	}
	for _, c := range cases {
		got := gatekeeperControl(c.in)
		switch {
		case c.want == "" && got != nil:
			t.Errorf("%q: want omitted, got %+v", c.in, got)
		case c.want != "" && (got == nil || got.Product != shared.AppControlGatekeeper || got.Mode != c.want):
			t.Errorf("%q: got %+v, want Gatekeeper/%s", c.in, got, c.want)
		}
	}
}

func TestFapolicydControl(t *testing.T) {
	unitFiles := map[string]string{"fapolicyd.service": "enabled"}
	active := map[string]string{"fapolicyd.service": "loaded"}
	cases := []struct {
		name      string
		active    map[string]string
		unitFiles map[string]string
		conf      string
		confOK    bool
		want      string // "" = omitted
	}{
		{"not installed", map[string]string{}, map[string]string{}, "", false, ""},
		{"installed, not running", map[string]string{}, unitFiles, "permissive = 0", true, shared.AppControlOff},
		{"running, enforcing", active, unitFiles, "# comment\npermissive = 0\nnice_val = 14", true, shared.AppControlEnforced},
		{"running, default permissive", active, unitFiles, "q_size = 800", true, shared.AppControlEnforced},
		{"running, permissive", active, unitFiles, "permissive = 1", true, shared.AppControlAudit},
		{"running, config unreadable", active, unitFiles, "", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := fapolicydControl(c.active, c.unitFiles, c.conf, c.confOK)
			switch {
			case c.want == "" && got != nil:
				t.Errorf("want omitted, got %+v", got)
			case c.want != "" && (got == nil || got.Product != shared.AppControlFapolicyd || got.Mode != c.want):
				t.Errorf("got %+v, want fapolicyd/%s", got, c.want)
			}
		})
	}
}

func TestAppControlJSONKeys(t *testing.T) {
	info := shared.SecurityInfo{
		AutoRun:            &shared.AutoRunInfo{AutoRunDisabled: shared.Bool(false)},
		ApplicationControl: &shared.ApplicationControlInfo{Product: shared.AppControlWDAC, Mode: shared.AppControlAudit},
	}
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	autorun, _ := m["autorun"].(map[string]any)
	if autorun["autorun_disabled"] != false {
		t.Errorf("a read false must be sent: %v", m["autorun"])
	}
	if _, ok := autorun["autoplay_disabled"]; ok {
		t.Errorf("an unread autoplay_disabled must be omitted: %v", autorun)
	}
	ac, _ := m["application_control"].(map[string]any)
	if ac["product"] != "WDAC" || ac["mode"] != "audit" {
		t.Errorf("application_control = %v", m["application_control"])
	}

	b, _ = json.Marshal(shared.SecurityInfo{})
	m = nil
	_ = json.Unmarshal(b, &m)
	if _, ok := m["autorun"]; ok {
		t.Error("nil autorun must be omitted")
	}
	if _, ok := m["application_control"]; ok {
		t.Error("nil application_control must be omitted")
	}
}

func TestParseWinComplianceProbeAppControl(t *testing.T) {
	p, ok := parseWinComplianceProbe(`{"WDAC":2,"AppLocker":"<AppLockerPolicy Version=\"1\" />"}`)
	if !ok || p.WDAC == nil || *p.WDAC != 2 || p.AppLocker == nil {
		t.Fatalf("got %+v ok=%v", p, ok)
	}
	if mode, ok := parseAppLockerPolicy(*p.AppLocker); !ok || mode != shared.AppControlOff {
		t.Errorf("AppLocker from probe = (%q, %v)", mode, ok)
	}
	p, _ = parseWinComplianceProbe(`{"GuestEnabled":false}`)
	if p.WDAC != nil || p.AppLocker != nil {
		t.Errorf("keys the script couldn't read must stay nil: %+v", p)
	}
}
