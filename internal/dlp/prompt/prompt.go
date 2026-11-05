// Package prompt asks the user, in their own session, what to do about a
// file DLP blocked under a block_override policy (#336, Compliance-OS#581):
// go ahead with a reason, ask IT for an exception, or leave it. It runs in
// the session helper, after the block (never while an OS hook waits), with
// the desktop's own dialog tool: a WinForms dialog through PowerShell on
// Windows, osascript on macOS, zenity or kdialog on Linux. Text reaches the
// tools through environment variables or plain arguments, never inside a
// script or through a shell. The reason is the user's free text: it is
// returned to the caller and never logged here.
package prompt

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"
)

// Choices.
const (
	ChoiceOverride = "override" // go ahead, with a reason
	ChoiceRequest  = "request"  // ask IT for an exception, with a reason
	ChoiceCancel   = "cancel"
)

// MaxReason is the longest reason kept (the server accepts 1–1000).
const MaxReason = 1000

// Labels on the buttons.
const (
	labelOverride = "Continue with a reason"
	labelRequest  = "Request an exception"
	labelCancel   = "Cancel"
	reasonPrompt  = "Why do you need to share this file? Your reason is sent to IT."
)

// Ask is what to show.
type Ask struct {
	Title       string
	Message     string
	CanOverride bool // the daily limit isn't used up
	CanRequest  bool
}

// ErrUnavailable means no dialog can be shown in this session.
var ErrUnavailable = errors.New("no dialog tool available in this session")

// Answer is the user's choice and reason (empty for cancel).
type Answer struct {
	Choice string
	Reason string
}

// cleanReason trims, drops invalid UTF-8 and control characters except
// newlines and tabs, and cuts to MaxReason runes.
func cleanReason(s string) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\t' || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > MaxReason {
		s = string([]rune(s)[:MaxReason])
	}
	return s
}

// finish turns a choice and raw reason into an Answer: a choice that needs
// a reason without one is a cancel.
func finish(choice, reason string) Answer {
	if choice != ChoiceOverride && choice != ChoiceRequest {
		return Answer{Choice: ChoiceCancel}
	}
	r := cleanReason(reason)
	if r == "" {
		return Answer{Choice: ChoiceCancel}
	}
	return Answer{Choice: choice, Reason: r}
}

// choiceForLabel maps a button label back to a choice.
func choiceForLabel(label string) string {
	switch strings.TrimSpace(label) {
	case labelOverride:
		return ChoiceOverride
	case labelRequest:
		return ChoiceRequest
	}
	return ChoiceCancel
}

// parseWindows reads the PowerShell dialog's JSON line.
func parseWindows(out string) Answer {
	var v struct {
		Choice string `json:"choice"`
		Reason string `json:"reason"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(out)), &v) != nil {
		return Answer{Choice: ChoiceCancel}
	}
	return finish(v.Choice, v.Reason)
}

// parseDarwin reads osascript's output: the button on the first line, the
// reason on the rest.
func parseDarwin(out string) Answer {
	button, reason, _ := strings.Cut(strings.TrimRight(out, "\n"), "\n")
	return finish(choiceForLabel(button), reason)
}

// zenityChoice reads the first zenity dialog: exit 0 is the OK button; the
// extra button prints its label and exits 1; Cancel exits 1 silently.
func zenityChoice(exitCode int, out string) string {
	if exitCode == 0 {
		return ChoiceOverride
	}
	return choiceForLabel(out)
}

// kdialogChoice reads kdialog --yesnocancel: 0 yes, 1 no, 2 cancel.
func kdialogChoice(exitCode int) string {
	switch exitCode {
	case 0:
		return ChoiceOverride
	case 1:
		return ChoiceRequest
	}
	return ChoiceCancel
}
