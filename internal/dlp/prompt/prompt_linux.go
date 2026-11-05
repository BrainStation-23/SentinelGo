//go:build linux

package prompt

import (
	"context"
	"errors"
	"os"
	"os/exec"
)

// Dialog tools, from fixed paths (never PATH).
var (
	zenityPaths  = []string{"/usr/bin/zenity", "/bin/zenity"}
	kdialogPaths = []string{"/usr/bin/kdialog", "/bin/kdialog"}
)

func find(paths []string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// run returns the tool's standard output and exit code; err only when it
// couldn't run at all.
func run(ctx context.Context, bin string, args ...string) (string, int, error) {
	out, err := exec.CommandContext(ctx, bin, args...).Output() // #nosec G204 -- fixed tool path; text as plain arguments, no shell
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(out), ee.ExitCode(), nil
	}
	return string(out), 0, err
}

// dialogTool is one tool's questions and how its answers read.
type dialogTool struct {
	question, reason func(Ask) []string
	answer           func(a Ask, code int, out string) string
}

var (
	zenity  = dialogTool{zenityQuestionArgs, zenityReasonArgs, zenityAnswer}
	kdialog = dialogTool{kdialogQuestionArgs, kdialogReasonArgs, func(a Ask, code int, _ string) string { return kdialogAnswer(a, code) }}
)

// Show asks with zenity (GNOME and most desktops) or kdialog (KDE).
func Show(ctx context.Context, a Ask) (Answer, error) {
	if !a.CanOverride && !a.CanRequest {
		return Answer{Choice: ChoiceCancel}, nil
	}
	bin, tool := find(zenityPaths), zenity
	if bin == "" {
		bin, tool = find(kdialogPaths), kdialog
	}
	if bin == "" {
		return Answer{}, ErrUnavailable
	}
	out, code, err := run(ctx, bin, tool.question(a)...)
	if err != nil {
		return Answer{}, err
	}
	choice := tool.answer(a, code, out)
	if choice == ChoiceCancel {
		return Answer{Choice: ChoiceCancel}, nil
	}
	reason, code, err := run(ctx, bin, tool.reason(a)...)
	if err != nil || code != 0 {
		return Answer{Choice: ChoiceCancel}, err
	}
	return finish(choice, reason), nil
}
