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

// Show asks with zenity (GNOME and most desktops) or kdialog (KDE).
func Show(ctx context.Context, a Ask) (Answer, error) {
	if !a.CanOverride && !a.CanRequest {
		return Answer{Choice: ChoiceCancel}, nil
	}
	if z := find(zenityPaths); z != "" {
		args := []string{"--question", "--title=" + a.Title, "--text=" + a.Message, "--cancel-label=" + labelCancel}
		single := labelOverride
		if !a.CanOverride {
			single = labelRequest
		}
		args = append(args, "--ok-label="+single)
		if a.CanOverride && a.CanRequest {
			args = append(args, "--extra-button="+labelRequest)
		}
		out, code, err := run(ctx, z, args...)
		if err != nil {
			return Answer{}, err
		}
		choice := zenityChoice(code, out)
		if !a.CanOverride && choice == ChoiceOverride {
			choice = ChoiceRequest
		}
		if choice == ChoiceCancel {
			return Answer{Choice: ChoiceCancel}, nil
		}
		reason, code, err := run(ctx, z, "--entry", "--title="+a.Title, "--text="+reasonPrompt)
		if err != nil || code != 0 {
			return Answer{Choice: ChoiceCancel}, err
		}
		return finish(choice, reason), nil
	}
	if k := find(kdialogPaths); k != "" {
		var args []string
		if a.CanOverride && a.CanRequest {
			args = []string{"--title", a.Title, "--yesnocancel", a.Message, "--yes-label", labelOverride, "--no-label", labelRequest, "--cancel-label", labelCancel}
		} else {
			single := labelOverride
			if !a.CanOverride {
				single = labelRequest
			}
			args = []string{"--title", a.Title, "--yesno", a.Message, "--yes-label", single, "--no-label", labelCancel}
		}
		_, code, err := run(ctx, k, args...)
		if err != nil {
			return Answer{}, err
		}
		choice := kdialogChoice(code)
		if !a.CanOverride || !a.CanRequest {
			switch {
			case code != 0:
				choice = ChoiceCancel
			case !a.CanOverride:
				choice = ChoiceRequest
			}
		}
		if choice == ChoiceCancel {
			return Answer{Choice: ChoiceCancel}, nil
		}
		reason, code, err := run(ctx, k, "--title", a.Title, "--inputbox", reasonPrompt)
		if err != nil || code != 0 {
			return Answer{Choice: ChoiceCancel}, err
		}
		return finish(choice, reason), nil
	}
	return Answer{}, ErrUnavailable
}
