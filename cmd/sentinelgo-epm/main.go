// Command sentinelgo-epm is the unprivileged, user-space EPM client. It runs
// as the interactive user (never privileged — SYSTEM/root/Administrator)
// and talks to the privileged sentinelgo agent over the platform EPM
// transport (Windows Named Pipe / Unix Domain Socket — see internal/epm's
// transport_windows.go/transport_unix.go) to request that a specific
// application be launched elevated. The agent — not this client — makes
// the allow/deny decision and re-derives the caller's identity from the OS
// at accept time, so this binary carries no privilege of its own; it is a
// thin request/response front end.
//
// Two modes:
//   - One-shot (default): submit a single elevation request and exit,
//     unchanged from every release before Phase 5.
//   - "-session": a long-lived per-user helper (normally autostarted — see
//     -install-session) that will render Phase 1's interaction verdicts
//     (Prompt/RequireJustification/RequireApproval) via internal/epm/prompt
//     once the privileged agent's Server actually sends them over a v2
//     connection. That server-side half (Server driving an OpPrompt/
//     OpPromptResult exchange instead of immediately applying
//     Outcome.FallbackVerdict) is not wired up yet — see runSession's doc
//     comment — so today "-session" starts, confirms a native Prompter is
//     available, and idles until told to stop. This mirrors
//     internal/epm/transportbe's Phase 7 status exactly: complete,
//     tested, agent-side plumbing with no live counterpart to talk to yet.
//
// One untagged file collapsing what was previously three (main_windows.go/
// main_linux.go/main_darwin.go), byte-identical apart from doc comments —
// epm.RequestElevation and prompt.New already vary per platform internally
// via their own build-tagged files, so nothing here needs to.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"sentinelgo/internal/epm"
	"sentinelgo/internal/epm/prompt"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("sentinelgo-epm", flag.ContinueOnError)
	appPath := fs.String("app", "", "absolute path of the application to run elevated (required unless -session, -install-session, or -uninstall-session is given)")
	commandLine := fs.String("args", "", "extra command-line arguments to pass to the application (or to -script, if set)")
	scriptPath := fs.String("script", "", "path of a script or installer payload to run via the interpreter given by -app")
	session := fs.Bool("session", false, "run as the long-lived per-user session helper instead of a one-shot request")
	installSession := fs.Bool("install-session", false, "register this binary to autostart -session in the current user's session, then exit")
	uninstallSession := fs.Bool("uninstall-session", false, "remove the autostart registration installed by -install-session, then exit")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: sentinelgo-epm -app <path> [-args \"<extra args>\"] [-script <path>]")
		fmt.Fprintln(fs.Output(), "       sentinelgo-epm -session")
		fmt.Fprintln(fs.Output(), "       sentinelgo-epm -install-session | -uninstall-session")
		fmt.Fprintln(fs.Output(), "Requests elevated execution of an application via the SentinelGo EPM policy engine,")
		fmt.Fprintln(fs.Output(), "or runs/manages the per-user session helper that renders elevation prompts.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	switch {
	case *installSession:
		return runInstallSession(true)
	case *uninstallSession:
		return runInstallSession(false)
	case *session:
		return runSession()
	}

	if *appPath == "" {
		// This also covers "-script requires -app": -app is unconditionally
		// required, so -script is never accepted without it.
		fs.Usage()
		return 2
	}

	result, err := epm.RequestElevation(*appPath, *commandLine, *scriptPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sentinelgo-epm: %v\n", err)
		return 1
	}

	if !result.Allowed {
		reason := result.Reason
		if result.Error != "" {
			reason = result.Error
		}
		fmt.Fprintf(os.Stderr, "Elevation denied: %s\n", reason)
		return 1
	}

	fmt.Printf("Elevation granted: launched PID %d\n", result.ProcessID)
	return 0
}

func runInstallSession(install bool) int {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sentinelgo-epm: resolve own executable path: %v\n", err)
		return 1
	}

	if install {
		err = newPlatformAutostart().Install(exe)
	} else {
		err = newPlatformAutostart().Uninstall()
	}
	if err != nil {
		verb := "install"
		if !install {
			verb = "uninstall"
		}
		fmt.Fprintf(os.Stderr, "sentinelgo-epm: %s session autostart: %v\n", verb, err)
		return 1
	}
	return 0
}

// runSession runs the long-lived per-user helper. It never creates a
// window itself outside of what a Prompter implementation renders (see
// internal/epm/prompt's package doc comment on why the privileged agent
// never does either) — this function's own job is just process lifecycle:
// confirm a Prompter is available, then block until asked to stop.
//
// STATUS: the wire half this depends on — Server (internal/epm/server.go)
// actually sending OpPrompt for an interaction verdict instead of always
// applying Outcome.FallbackVerdict, and this process receiving it over a
// persistent v2 connection and replying with OpPromptResult — is not
// implemented. Building that loop without a live counterpart to exchange
// messages with would be unverifiable scaffolding pretending to be a
// working feature; internal/epm/transportbe's Phase 7 RPCs are in the
// identical position (complete, tested, agent-side-only). Wiring the two
// together is future work once there is a concrete reason to (a real
// interaction-verdict rule an operator wants to ship).
func runSession() int {
	p := newPlatformPrompter()
	if !p.Available() {
		log.Printf("sentinelgo-epm: session helper starting, but no native prompt mechanism is available on this system")
	} else {
		log.Printf("sentinelgo-epm: session helper started (prompt backend available)")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	select {
	case <-sigChan:
		log.Printf("sentinelgo-epm: session helper received shutdown signal, stopping")
	case <-ctx.Done():
	}
	return 0
}

// newPlatformPrompter is a seam over prompt.NewWindowsPrompter/
// NewLinuxPrompter/NewDarwinPrompter, set by an init() in each platform's
// platform_<os>.go file in this package — kept out of main.go itself so
// this file stays untagged.
var newPlatformPrompter = func() prompt.Prompter { return noopPrompter{} }

// noopPrompter is the untagged default — unreachable in a real build
// (exactly one platform file is always compiled in) but safe to call into
// regardless, rather than leaving runSession one missing init() away from
// a nil-interface panic.
type noopPrompter struct{}

func (noopPrompter) Available() bool { return false }
func (noopPrompter) Confirm(string, string) (bool, error) {
	return false, fmt.Errorf("sentinelgo-epm: no prompt mechanism for this platform")
}
func (noopPrompter) Justify(string, string) (string, bool, error) {
	return "", false, fmt.Errorf("sentinelgo-epm: no prompt mechanism for this platform")
}
func (noopPrompter) Notify(string, string) error {
	return fmt.Errorf("sentinelgo-epm: no prompt mechanism for this platform")
}

// autostart registers/removes the per-user "-session" autostart entry:
// Windows HKCU\...\Run, Linux XDG ~/.config/autostart/*.desktop, macOS
// ~/Library/LaunchAgents/*.plist — see each platform_<os>.go file.
type autostart interface {
	Install(exePath string) error
	Uninstall() error
}

// newPlatformAutostart is set by an init() in each platform_<os>.go file,
// the same seam pattern as newPlatformPrompter.
var newPlatformAutostart = func() autostart { return noopAutostart{} }

// noopAutostart is the untagged default — like newPlatformPrompter's nil
// default, unreachable in a real build (exactly one platform file is
// always compiled in), kept only so this file itself has no build tag.
type noopAutostart struct{}

func (noopAutostart) Install(string) error {
	return fmt.Errorf("sentinelgo-epm: no autostart mechanism for this platform")
}
func (noopAutostart) Uninstall() error {
	return fmt.Errorf("sentinelgo-epm: no autostart mechanism for this platform")
}
