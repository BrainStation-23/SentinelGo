//go:build windows

package prompt

import (
	"strings"

	"golang.org/x/sys/windows"
)

// WindowsPrompter implements Confirm/Notify via the standard Win32
// MessageBoxW — deliberately chosen over TaskDialogIndirect, which needs
// the comctl32 v6 common-controls library active via an application
// manifest (cmd/sentinelgo-epm carries none) and a substantially more
// complex, union-containing config struct with real risk of getting the
// field layout subtly wrong with no way to verify it short of an
// interactive Windows desktop. MessageBoxW is simpler, has shipped
// unchanged since Windows 2000, needs no manifest, and is already fully
// wrapped by golang.org/x/sys/windows (windows.MessageBox) with no manual
// struct packing required — the same "prefer the proven, lower-risk API"
// judgment applied throughout this codebase (e.g. EvtSubscribe's
// signal-event pattern over a true async callback).
//
// Justify (free-text input) has no equivalent built-in Win32 common
// dialog — the plan's own sketch was a ~250-line hand-rolled
// CreateWindowExW + EDIT control + message pump, which carries the same
// unverifiable-struct/callback risk as TaskDialogIndirect, at even greater
// scope. This implementation instead shells out to a short PowerShell/
// WinForms script (powershell_windows.go) — .NET WinForms has been a
// stable, unchanged API for two decades and is present on every supported
// Windows version, so this trades a few hundred milliseconds of process
// + assembly-load startup latency (well within interactive-prompt
// tolerance) for a dramatically smaller, lower-risk amount of custom Win32
// plumbing to get right without hardware to test against.
type WindowsPrompter struct {
	messageBox func(hwnd windows.HWND, text, caption *uint16, boxtype uint32) (int32, error)
	inputBox   func(title, message string) (text string, ok bool, err error)
}

// NewWindowsPrompter builds a WindowsPrompter using the real OS.
func NewWindowsPrompter() *WindowsPrompter {
	return &WindowsPrompter{messageBox: windows.MessageBox, inputBox: powershellInputBox}
}

// Available is always true: MessageBoxW ships with every Windows install.
func (p *WindowsPrompter) Available() bool { return true }

// idYes is MessageBoxW's IDYES return value (winuser.h) — not exposed by
// golang.org/x/sys/windows, so declared locally; stable since Windows 2.0.
// MB_YESNO's only other outcome is IDNO, so comparing against idYes alone
// already covers both cases ("not yes" means "no").
const idYes = 6

const mbFlagsConfirm = windows.MB_YESNO | windows.MB_ICONQUESTION | windows.MB_SETFOREGROUND | windows.MB_TOPMOST
const mbFlagsNotify = windows.MB_OK | windows.MB_ICONINFORMATION | windows.MB_SETFOREGROUND | windows.MB_TOPMOST

func (p *WindowsPrompter) Confirm(title, message string) (bool, error) {
	textPtr, err := windows.UTF16PtrFromString(message)
	if err != nil {
		return false, err
	}
	captionPtr, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return false, err
	}
	ret, err := p.messageBox(0, textPtr, captionPtr, mbFlagsConfirm)
	if err != nil {
		return false, err
	}
	return ret == idYes, nil
}

func (p *WindowsPrompter) Notify(title, message string) error {
	textPtr, err := windows.UTF16PtrFromString(message)
	if err != nil {
		return err
	}
	captionPtr, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return err
	}
	_, err = p.messageBox(0, textPtr, captionPtr, mbFlagsNotify)
	return err
}

func (p *WindowsPrompter) Justify(title, message string) (string, bool, error) {
	return p.inputBox(title, message)
}

// escapePowerShellSingleQuoted escapes s for embedding inside a PowerShell
// single-quoted string literal, where the only special character is the
// single quote itself, escaped by doubling it.
func escapePowerShellSingleQuoted(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
