//go:build darwin

package prompt

import (
	"errors"
	"testing"
)

func TestParseButtonReturned(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
		want   string
		wantOK bool
	}{
		{"confirm yes", "button returned:Yes\n", "Yes", true},
		{"confirm no", "button returned:No\n", "No", true},
		{"justify ok with text", "button returned:OK, text returned:hello world\n", "OK", true},
		{"no match", "something else\n", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseButtonReturned(tc.stdout)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("parseButtonReturned(%q) = (%q, %v), want (%q, %v)", tc.stdout, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestParseTextReturned(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
		want   string
		wantOK bool
	}{
		{"simple", "button returned:OK, text returned:hello\n", "hello", true},
		{"text with commas", "button returned:OK, text returned:a, b, c\n", "a, b, c", true},
		{"no text field", "button returned:Yes\n", "", false},
		{"empty text", "button returned:OK, text returned:\n", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseTextReturned(tc.stdout)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("parseTextReturned(%q) = (%q, %v), want (%q, %v)", tc.stdout, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestEscapeAppleScriptString(t *testing.T) {
	cases := map[string]string{
		`plain`:             `plain`,
		`say "hi"`:          `say \"hi\"`,
		`back\slash`:        `back\\slash`,
		`both\ and "quote"`: `both\\ and \"quote\"`,
	}
	for in, want := range cases {
		if got := escapeAppleScriptString(in); got != want {
			t.Errorf("escapeAppleScriptString(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsUserCancelled(t *testing.T) {
	cases := map[string]bool{
		"execution error: User canceled. (-128)": true,
		"some other error":                       false,
		"":                                       false,
	}
	for in, want := range cases {
		if got := isUserCancelled(in); got != want {
			t.Errorf("isUserCancelled(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestDarwinPrompter_Available(t *testing.T) {
	p := &DarwinPrompter{}
	if !p.Available() {
		t.Error("Available() = false, want true (osascript ships with every macOS install)")
	}
}

func TestDarwinPrompter_Confirm(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want bool
	}{
		{"yes", "button returned:Yes\n", true},
		{"no", "button returned:No\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &DarwinPrompter{runCommand: func(string) (string, int, error) { return tc.out, 0, nil }}
			got, err := p.Confirm("Title", "Message")
			if err != nil {
				t.Fatalf("Confirm() error = %v", err)
			}
			if got != tc.want {
				t.Errorf("Confirm() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDarwinPrompter_Confirm_CancelledIsFalseNotError(t *testing.T) {
	p := &DarwinPrompter{runCommand: func(string) (string, int, error) {
		return "", 1, &osascriptError{stderr: "execution error: User canceled. (-128)"}
	}}
	got, err := p.Confirm("Title", "Message")
	if err != nil {
		t.Fatalf("Confirm() error = %v, want nil (cancel is not an error)", err)
	}
	if got {
		t.Error("Confirm() = true, want false on cancel")
	}
}

func TestDarwinPrompter_Confirm_RealErrorPropagates(t *testing.T) {
	p := &DarwinPrompter{runCommand: func(string) (string, int, error) {
		return "", 1, errors.New("no display")
	}}
	if _, err := p.Confirm("Title", "Message"); err == nil {
		t.Error("Confirm() error = nil, want a genuine error propagated")
	}
}

func TestDarwinPrompter_Justify(t *testing.T) {
	p := &DarwinPrompter{runCommand: func(string) (string, int, error) {
		return "button returned:OK, text returned:my justification\n", 0, nil
	}}
	text, ok, err := p.Justify("Title", "Message")
	if err != nil {
		t.Fatalf("Justify() error = %v", err)
	}
	if !ok || text != "my justification" {
		t.Errorf("Justify() = (%q, %v), want (my justification, true)", text, ok)
	}
}

func TestDarwinPrompter_Justify_Cancelled(t *testing.T) {
	p := &DarwinPrompter{runCommand: func(string) (string, int, error) {
		return "", 1, &osascriptError{stderr: "execution error: User canceled. (-128)"}
	}}
	text, ok, err := p.Justify("Title", "Message")
	if err != nil {
		t.Fatalf("Justify() error = %v", err)
	}
	if ok || text != "" {
		t.Errorf("Justify() = (%q, %v), want (\"\", false) on cancel", text, ok)
	}
}

func TestDarwinPrompter_Notify(t *testing.T) {
	var gotScript string
	p := &DarwinPrompter{runCommand: func(script string) (string, int, error) {
		gotScript = script
		return "", 0, nil
	}}
	if err := p.Notify("Title", "Message"); err != nil {
		t.Fatalf("Notify() error = %v", err)
	}
	if gotScript == "" {
		t.Error("Notify() did not run any script")
	}
}
