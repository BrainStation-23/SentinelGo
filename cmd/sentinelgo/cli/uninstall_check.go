package cli

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"strings"

	"sentinelgo/internal/config"
	"sentinelgo/internal/uninstallprotect"
)

// UninstallCheckCommand is `sentinelgo uninstall-check` (#566): the MSI's
// uninstall runs it before removing anything. Exit 0 lets the uninstall go
// on, any other code aborts it.
const UninstallCheckCommand = "uninstall-check"

// Exit codes of uninstall-check.
const (
	uninstallCheckAllowed = 0
	uninstallCheckBlocked = 1
	uninstallCheckUsage   = 2
)

// RunUninstallCheck runs `sentinelgo uninstall-check [-token TOKEN|-]
// [-config PATH]` and returns the exit code. With -token -, the token is read
// from stdin. The token is never printed.
func RunUninstallCheck(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(UninstallCheckCommand, flag.ContinueOnError)
	fs.SetOutput(stderr)
	token := fs.String("token", "", "the device's uninstall token from the console, or - to read it from stdin")
	cfgPath := fs.String("config", "", "config.json of the install (default: the standard path)")
	if err := fs.Parse(args); err != nil {
		return uninstallCheckUsage
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintln(stderr, "usage: sentinelgo uninstall-check [-token TOKEN|-] [-config PATH]")
		return uninstallCheckUsage
	}
	tok, err := ReadUninstallToken(*token, stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %v\n", UninstallCheckCommand, err)
		return uninstallCheckUsage
	}
	if CheckUninstallToken(*cfgPath, tok, stdout, stderr) {
		return uninstallCheckAllowed
	}
	return uninstallCheckBlocked
}

// ReadUninstallToken returns value, or the first line of stdin when value is
// "-".
func ReadUninstallToken(value string, stdin io.Reader) (string, error) {
	if value != "-" {
		return value, nil
	}
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("no token on stdin")
	}
	return strings.TrimSpace(line), nil
}

// CheckUninstallToken checks token against the synced uninstall protection
// of the install whose config is cfgPath (the standard path when empty),
// prints the decision and reports whether the uninstall may go on.
func CheckUninstallToken(cfgPath, token string, stdout, stderr io.Writer) bool {
	if cfgPath == "" {
		cfgPath = config.GetDefaultConfigPath()
	}
	d, err := uninstallprotect.CheckFile(uninstallprotect.StatePath(cfgPath), token)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: ignoring the uninstall protection state: %v\n", UninstallCheckCommand, err)
	}
	if d.Allowed() {
		_, _ = fmt.Fprintln(stdout, d.String())
		return true
	}
	_, _ = fmt.Fprintln(stderr, d.String())
	return false
}
