// Package prompt implements Phase 5's native, per-platform interactive
// dialogs for EPM's interaction verdicts (Prompt, RequireJustification,
// RequireApproval — see internal/epm/verdict.go's Verdict.NeedsInteraction).
//
// The privileged sentinelgo agent never creates a window. A background
// service rendering UI is the classic shatter-attack surface (a malicious
// or compromised process in the interactive session sending window
// messages to a privileged window), and Windows Session 0 isolation makes
// it structurally impossible for a service to show UI in the user's
// desktop anyway on any modern Windows version. Every Prompter
// implementation here is meant to run from cmd/sentinelgo-epm's
// unprivileged, per-user "-session" helper — never from cmd/sentinelgo
// itself.
package prompt

// Prompter renders interactive dialogs on behalf of the session helper.
// Every method blocks until the user responds (or the platform's own
// timeout/giving-up mechanism fires, where supported) — there is no
// separate cancellation channel because the underlying native dialogs
// (TaskDialog, zenity, osascript's display dialog) are themselves
// synchronous, modal calls.
type Prompter interface {
	// Available reports whether this platform's prompt mechanism can
	// actually render right now — e.g. a Linux box with neither zenity nor
	// kdialog installed, or no interactive display session at all. Callers
	// should treat Available()==false as "no prompt possible", the same
	// fail-closed direction Outcome.FallbackVerdict already takes when no
	// session helper is connected at all.
	Available() bool

	// Confirm shows a yes/no confirmation dialog and reports whether the
	// user chose yes.
	Confirm(title, message string) (bool, error)

	// Justify shows a dialog with a free-text input field. ok is false if
	// the user cancelled (justification is then meaningless and must not
	// be used).
	Justify(title, message string) (justification string, ok bool, err error)

	// Notify shows an information-only dialog or notification requiring no
	// response.
	Notify(title, message string) error
}
