//go:build linux

package prompt

import (
	"os/exec"
	"strings"
)

// LinuxPrompter shells out to zenity first, falling back to kdialog —
// covering GNOME/GTK and KDE/Qt desktops respectively, the two toolkits
// virtually every Linux desktop environment is built on one of. Available()
// reports false (and every other method errors) when neither is installed,
// which the plan explicitly allows as the third fallback rung.
type LinuxPrompter struct {
	// lookPath and runCommand are seams so tests never depend on zenity or
	// kdialog actually being installed, matching the package-level
	// function-var pattern used throughout internal/epm.
	lookPath   func(name string) (string, error)
	runCommand func(name string, args ...string) (stdout string, exitCode int, err error)
}

// NewLinuxPrompter builds a LinuxPrompter using the real OS (exec.LookPath,
// a real subprocess).
func NewLinuxPrompter() *LinuxPrompter {
	return &LinuxPrompter{lookPath: exec.LookPath, runCommand: runCommandReal}
}

// dialogBackend identifies which tool a LinuxPrompter resolved to.
type dialogBackend int

const (
	backendNone dialogBackend = iota
	backendZenity
	backendKdialog
)

func (p *LinuxPrompter) backend() dialogBackend {
	if _, err := p.lookPath("zenity"); err == nil {
		return backendZenity
	}
	if _, err := p.lookPath("kdialog"); err == nil {
		return backendKdialog
	}
	return backendNone
}

func (p *LinuxPrompter) Available() bool {
	return p.backend() != backendNone
}

func (p *LinuxPrompter) Confirm(title, message string) (bool, error) {
	switch p.backend() {
	case backendZenity:
		_, exitCode, err := p.runCommand("zenity", "--question", "--title", title, "--text", message)
		if err != nil {
			return false, err
		}
		return exitCode == 0, nil
	case backendKdialog:
		_, exitCode, err := p.runCommand("kdialog", "--title", title, "--yesno", message)
		if err != nil {
			return false, err
		}
		return exitCode == 0, nil
	default:
		return false, errNoDialogBackend
	}
}

func (p *LinuxPrompter) Justify(title, message string) (string, bool, error) {
	switch p.backend() {
	case backendZenity:
		out, exitCode, err := p.runCommand("zenity", "--entry", "--title", title, "--text", message)
		if err != nil {
			return "", false, err
		}
		if exitCode != 0 {
			return "", false, nil
		}
		return strings.TrimRight(out, "\n"), true, nil
	case backendKdialog:
		out, exitCode, err := p.runCommand("kdialog", "--title", title, "--inputbox", message)
		if err != nil {
			return "", false, err
		}
		if exitCode != 0 {
			return "", false, nil
		}
		return strings.TrimRight(out, "\n"), true, nil
	default:
		return "", false, errNoDialogBackend
	}
}

func (p *LinuxPrompter) Notify(title, message string) error {
	switch p.backend() {
	case backendZenity:
		_, _, err := p.runCommand("zenity", "--info", "--title", title, "--text", message)
		return err
	case backendKdialog:
		_, _, err := p.runCommand("kdialog", "--title", title, "--msgbox", message)
		return err
	default:
		return errNoDialogBackend
	}
}
