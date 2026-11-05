//go:build darwin

package prompt

import (
	"context"
	"errors"
	"os/exec"
)

// darwinScript shows one dialog with a text field; the text comes from the
// environment, so no user or policy text is ever part of the script. The
// Cancel button makes osascript fail with "User canceled".
const darwinScript = `set t to system attribute "SG_TITLE"
set m to system attribute "SG_MSG"
set b to {"Cancel"}
if (system attribute "SG_CAN_REQUEST") is "1" then set end of b to "Request an exception"
if (system attribute "SG_CAN_OVERRIDE") is "1" then set end of b to "Continue with a reason"
set r to display dialog (m & return & return & (system attribute "SG_PROMPT")) with title t default answer "" buttons b default button (count of b) cancel button "Cancel" with icon caution
return (button returned of r) & linefeed & (text returned of r)`

func flag(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// Show asks with an AppleScript dialog.
func Show(ctx context.Context, a Ask) (Answer, error) {
	if !a.CanOverride && !a.CanRequest {
		return Answer{Choice: ChoiceCancel}, nil
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/osascript", "-e", darwinScript) // #nosec G204 -- fixed script; text arrives via environment
	cmd.Env = append(cmd.Environ(), "SG_TITLE="+a.Title, "SG_MSG="+a.Message, "SG_PROMPT="+reasonPrompt,
		"SG_CAN_OVERRIDE="+flag(a.CanOverride), "SG_CAN_REQUEST="+flag(a.CanRequest))
	out, err := cmd.Output()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return Answer{Choice: ChoiceCancel}, nil // Cancel
	}
	if err != nil {
		return Answer{}, err
	}
	return parseDarwin(string(out)), nil
}
