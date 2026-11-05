package prompt

import (
	"strings"
	"testing"
)

func TestParsers(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  Answer
		want Answer
	}{
		{"windows override", parseWindows(`{"choice":"override","reason":"  customer asked  "}`), Answer{ChoiceOverride, "customer asked"}},
		{"windows request", parseWindows(`{"choice":"request","reason":"quarterly report"}`), Answer{ChoiceRequest, "quarterly report"}},
		{"windows no reason", parseWindows(`{"choice":"override","reason":"   "}`), Answer{Choice: ChoiceCancel}},
		{"windows cancel", parseWindows(`{"choice":"cancel","reason":"x"}`), Answer{Choice: ChoiceCancel}},
		{"windows junk", parseWindows(`not json`), Answer{Choice: ChoiceCancel}},
		{"windows unknown choice", parseWindows(`{"choice":"delete-everything","reason":"x"}`), Answer{Choice: ChoiceCancel}},
		{"darwin override", parseDarwin("Continue with a reason\nfor the audit\n"), Answer{ChoiceOverride, "for the audit"}},
		{"darwin request, multi-line", parseDarwin("Request an exception\nline one\nline two"), Answer{ChoiceRequest, "line one\nline two"}},
		{"darwin empty", parseDarwin("Continue with a reason\n"), Answer{Choice: ChoiceCancel}},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, tc.got, tc.want)
		}
	}
}

func TestLinuxChoices(t *testing.T) {
	if zenityChoice(0, "") != ChoiceOverride || zenityChoice(1, "Request an exception\n") != ChoiceRequest || zenityChoice(1, "") != ChoiceCancel {
		t.Fatal("zenity")
	}
	if kdialogChoice(0) != ChoiceOverride || kdialogChoice(1) != ChoiceRequest || kdialogChoice(2) != ChoiceCancel {
		t.Fatal("kdialog")
	}
}

func TestCleanReason(t *testing.T) {
	long := strings.Repeat("é", 1200)
	if got := cleanReason(long); len([]rune(got)) != MaxReason {
		t.Fatalf("cut to %d", len([]rune(got)))
	}
	if got := cleanReason("a\x00b\x1bc\n\td\xff"); got != "abc\n\td" {
		t.Fatalf("%q", got)
	}
}

func TestLinuxDialogArgs(t *testing.T) {
	both := Ask{Title: "T", Message: "-m", CanOverride: true, CanRequest: true}
	onlyReq := Ask{Title: "T", Message: "m", CanRequest: true}
	onlyOver := Ask{Title: "T", Message: "m", CanOverride: true}

	z := strings.Join(zenityQuestionArgs(both), "|")
	if !strings.Contains(z, "--text=-m") || !strings.Contains(z, "--ok-label=Continue with a reason") || !strings.Contains(z, "--extra-button=Request an exception") {
		t.Fatalf("zenity both: %s", z)
	}
	if z := strings.Join(zenityQuestionArgs(onlyReq), "|"); !strings.Contains(z, "--ok-label=Request an exception") || strings.Contains(z, "--extra-button") {
		t.Fatalf("zenity request only: %s", z)
	}
	if zenityAnswer(onlyReq, 0, "") != ChoiceRequest || zenityAnswer(both, 1, "Request an exception\n") != ChoiceRequest || zenityAnswer(both, 1, "") != ChoiceCancel {
		t.Fatal("zenity answers")
	}
	if r := zenityReasonArgs(both); r[0] != "--entry" {
		t.Fatalf("zenity reason %v", r)
	}

	if k := kdialogQuestionArgs(both); k[2] != "--yesnocancel" || k[3] != "-m" {
		t.Fatalf("kdialog both %v", k)
	}
	if k := kdialogQuestionArgs(onlyOver); k[2] != "--yesno" || k[5] != "Continue with a reason" {
		t.Fatalf("kdialog one %v", k)
	}
	for _, tc := range []struct {
		a    Ask
		code int
		want string
	}{{both, 0, ChoiceOverride}, {both, 1, ChoiceRequest}, {both, 2, ChoiceCancel},
		{onlyReq, 0, ChoiceRequest}, {onlyOver, 0, ChoiceOverride}, {onlyOver, 1, ChoiceCancel}} {
		if got := kdialogAnswer(tc.a, tc.code); got != tc.want {
			t.Errorf("kdialog %+v %d: %s", tc.a, tc.code, got)
		}
	}
	if r := kdialogReasonArgs(both); r[2] != "--inputbox" {
		t.Fatalf("kdialog reason %v", r)
	}
}
