//go:build linux

// Command sentinelgo-epm is the unprivileged, user-space EPM client. It runs
// as the interactive console user (never as root) and talks to the
// privileged sentinelgo agent over the EPM Unix Domain Socket
// (internal/epm.SocketPath) to request that a specific application be
// launched elevated. The agent — not this client — makes the allow/deny
// decision and re-derives the caller's identity from the OS (SO_PEERCRED,
// checked against the active logind session), so this binary carries no
// privilege of its own; it is a thin request/response front end.
package main

import (
	"flag"
	"fmt"
	"os"

	"sentinelgo/internal/epm"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("sentinelgo-epm", flag.ContinueOnError)
	appPath := fs.String("app", "", "absolute path of the application to run elevated (required)")
	commandLine := fs.String("args", "", "extra command-line arguments to pass to the application (or to -script, if set)")
	scriptPath := fs.String("script", "", "path of a script or installer payload to run via the interpreter given by -app")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: sentinelgo-epm -app <path> [-args \"<extra args>\"] [-script <path>]")
		fmt.Fprintln(fs.Output(), "Requests elevated execution of an application via the SentinelGo EPM policy engine.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
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
