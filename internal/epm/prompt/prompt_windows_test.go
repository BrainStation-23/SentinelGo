//go:build windows

package prompt

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsPrompter_Available(t *testing.T) {
	p := &WindowsPrompter{}
	if !p.Available() {
		t.Error("Available() = false, want true (MessageBoxW always ships with Windows)")
	}
}

func TestWindowsPrompter_Confirm(t *testing.T) {
	cases := []struct {
		name    string
		ret     int32
		mbErr   error
		want    bool
		wantErr bool
	}{
		{"yes clicked", idYes, nil, true, false},
		{"no clicked", 7, nil, false, false},
		{"messagebox error", 0, errors.New("boom"), false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotFlags uint32
			p := &WindowsPrompter{messageBox: func(_ windows.HWND, _, _ *uint16, boxtype uint32) (int32, error) {
				gotFlags = boxtype
				return tc.ret, tc.mbErr
			}}
			got, err := p.Confirm("Title", "Message")
			if (err != nil) != tc.wantErr {
				t.Fatalf("Confirm() error = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Errorf("Confirm() = %v, want %v", got, tc.want)
			}
			if gotFlags != mbFlagsConfirm {
				t.Errorf("boxtype = %#x, want %#x", gotFlags, mbFlagsConfirm)
			}
		})
	}
}

func TestWindowsPrompter_Notify(t *testing.T) {
	var gotFlags uint32
	p := &WindowsPrompter{messageBox: func(_ windows.HWND, _, _ *uint16, boxtype uint32) (int32, error) {
		gotFlags = boxtype
		return 1, nil
	}}
	if err := p.Notify("Title", "Message"); err != nil {
		t.Fatalf("Notify() error = %v", err)
	}
	if gotFlags != mbFlagsNotify {
		t.Errorf("boxtype = %#x, want %#x", gotFlags, mbFlagsNotify)
	}
}

func TestWindowsPrompter_Notify_PropagatesError(t *testing.T) {
	p := &WindowsPrompter{messageBox: func(_ windows.HWND, _, _ *uint16, _ uint32) (int32, error) {
		return 0, errors.New("boom")
	}}
	if err := p.Notify("Title", "Message"); err == nil {
		t.Error("Notify() error = nil, want the messageBox error propagated")
	}
}

func TestWindowsPrompter_Justify_DelegatesToInputBox(t *testing.T) {
	var gotTitle, gotMessage string
	p := &WindowsPrompter{inputBox: func(title, message string) (string, bool, error) {
		gotTitle, gotMessage = title, message
		return "the answer", true, nil
	}}
	text, ok, err := p.Justify("Title", "Message")
	if err != nil {
		t.Fatalf("Justify() error = %v", err)
	}
	if !ok || text != "the answer" {
		t.Errorf("Justify() = (%q, %v), want (the answer, true)", text, ok)
	}
	if gotTitle != "Title" || gotMessage != "Message" {
		t.Errorf("inputBox called with (%q, %q)", gotTitle, gotMessage)
	}
}

func TestEscapePowerShellSingleQuoted(t *testing.T) {
	cases := map[string]string{
		"plain":             "plain",
		"it's":              "it''s",
		"''already":         "''''already",
		"":                  "",
		"multi's's's quote": "multi''s''s''s quote",
	}
	for in, want := range cases {
		if got := escapePowerShellSingleQuoted(in); got != want {
			t.Errorf("escapePowerShellSingleQuoted(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseInputBoxOutput(t *testing.T) {
	cases := []struct {
		name     string
		stdout   string
		wantText string
		wantOK   bool
		wantErr  bool
	}{
		{"ok with text", "OK:hello world\n", "hello world", true, false},
		{"ok with empty text", "OK:\n", "", true, false},
		{"cancel", "CANCEL:\n", "", false, false},
		{"cancel with trailing whitespace", "  CANCEL:  \n", "", false, false},
		{"malformed", "garbage\n", "", false, true},
		{"empty", "", "", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text, ok, err := parseInputBoxOutput(tc.stdout)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseInputBoxOutput(%q) error = %v, wantErr %v", tc.stdout, err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if text != tc.wantText || ok != tc.wantOK {
				t.Errorf("parseInputBoxOutput(%q) = (%q, %v), want (%q, %v)", tc.stdout, text, ok, tc.wantText, tc.wantOK)
			}
		})
	}
}
