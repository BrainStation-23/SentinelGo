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
