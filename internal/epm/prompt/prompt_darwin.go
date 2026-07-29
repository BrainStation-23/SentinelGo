//go:build darwin

package prompt

import "strings"

// DarwinPrompter shells out to osascript, driving AppleScript's built-in
// "display dialog"/"display notification" commands — the standard native
// dialog mechanism on macOS, requiring no additional installed tooling
// (unlike Linux's zenity/kdialog).
type DarwinPrompter struct {
	// runCommand is a seam so tests never depend on a live GUI session.
	runCommand func(script string) (stdout string, exitCode int, err error)
}

// NewDarwinPrompter builds a DarwinPrompter using the real OS (a real
// osascript subprocess).
func NewDarwinPrompter() *DarwinPrompter {
	return &DarwinPrompter{runCommand: runOsascriptReal}
}

// Available is always true on Darwin: osascript ships with every macOS
// install. A headless session (e.g. over SSH with no active window server)
// still fails at dialog-display time, which Confirm/Justify/Notify each
// surface as an ordinary error rather than something Available can predict
// in advance.
func (p *DarwinPrompter) Available() bool { return true }

func (p *DarwinPrompter) Confirm(title, message string) (bool, error) {
	script := `display dialog "` + escapeAppleScriptString(message) + `" with title "` + escapeAppleScriptString(title) +
		`" buttons {"No", "Yes"} default button "Yes"`
	out, exitCode, err := p.runCommand(script)
	if err != nil {
		if exitCode != 0 && isUserCancelled(err.Error()) {
			return false, nil
		}
		return false, err
	}
	button, ok := parseButtonReturned(out)
	return ok && button == "Yes", nil
}

func (p *DarwinPrompter) Justify(title, message string) (string, bool, error) {
	script := `display dialog "` + escapeAppleScriptString(message) + `" with title "` + escapeAppleScriptString(title) +
		`" default answer "" buttons {"Cancel", "OK"} default button "OK"`
	out, exitCode, err := p.runCommand(script)
	if err != nil {
		if exitCode != 0 && isUserCancelled(err.Error()) {
			return "", false, nil
		}
		return "", false, err
	}
	button, ok := parseButtonReturned(out)
	if !ok || button != "OK" {
		return "", false, nil
	}
	text, _ := parseTextReturned(out)
	return text, true, nil
}

func (p *DarwinPrompter) Notify(title, message string) error {
	script := `display notification "` + escapeAppleScriptString(message) + `" with title "` + escapeAppleScriptString(title) + `"`
	_, _, err := p.runCommand(script)
	return err
}

// escapeAppleScriptString escapes a Go string for embedding inside an
// AppleScript double-quoted string literal.
func escapeAppleScriptString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// isUserCancelled reports whether osascript's stderr text matches
// AppleScript's standard "user cancelled" error (-128), which "display
// dialog" raises when Cancel is clicked or the dialog is closed — a normal,
// expected outcome (ok=false), not a real failure.
func isUserCancelled(stderr string) bool {
	return strings.Contains(stderr, "-128") || strings.Contains(stderr, "User canceled")
}

// parseButtonReturned extracts the "button returned:X" field from
// osascript's stdout, split out for testability without a live osascript.
func parseButtonReturned(stdout string) (string, bool) {
	for _, field := range strings.Split(stdout, ",") {
		field = strings.TrimSpace(field)
		if v, ok := strings.CutPrefix(field, "button returned:"); ok {
			return strings.TrimSpace(v), true
		}
	}
	return "", false
}

// parseTextReturned extracts the "text returned:X" field. Split on ", "
// only for the FIRST occurrence, since the returned text itself may
// legitimately contain commas — button returned always comes first and has
// no commas of its own, so anchoring on the "text returned:" prefix and
// taking everything after it is correct.
func parseTextReturned(stdout string) (string, bool) {
	idx := strings.Index(stdout, "text returned:")
	if idx == -1 {
		return "", false
	}
	text := stdout[idx+len("text returned:"):]
	return strings.TrimRight(text, "\n"), true
}
