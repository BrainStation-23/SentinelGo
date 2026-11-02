package cli

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"strings"

	"sentinelgo/internal/config"
	"sentinelgo/internal/enrollment"
)

// EnrollCommand is `sentinelgo enroll`: save a first-boot enrollment token
// for the agent (#358). Installers run it, e.g. the generic MSI's custom
// action with its ENROLLMENT_TOKEN and SERVER_URL properties.
const EnrollCommand = "enroll"

// RunEnroll runs `sentinelgo enroll -token TOKEN|- -server-url URL
// -anon-key KEY [-config PATH]` and returns the exit code. With -token -, the
// token is read from stdin, so it doesn't show in the process list.
func RunEnroll(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	token := fs.String("token", "", "the single-use enrollment token, or - to read it from stdin")
	serverURL := fs.String("server-url", "", "the API URL (https)")
	anonKey := fs.String("anon-key", "", "the API's public (anon) key")
	cfgPath := fs.String("config", "", "config.json of the install (default: the standard path)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *token == "-" {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && line == "" {
			_, _ = fmt.Fprintln(stderr, "enroll: no token on stdin")
			return 2
		}
		*token = strings.TrimSpace(line)
	}
	if *token == "" || *serverURL == "" || *anonKey == "" {
		_, _ = fmt.Fprintln(stderr, "usage: sentinelgo enroll -token TOKEN|- -server-url URL -anon-key KEY [-config PATH]")
		return 2
	}

	load := loadDefaultConfig
	if *cfgPath != "" {
		load = func() (*config.Config, error) { return config.Load(*cfgPath) }
	}
	cfg, err := load()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "enroll: %v\n", err)
		return 1
	}
	if !enrollment.Needed(cfg) {
		_, _ = fmt.Fprintln(stdout, "This agent is already configured; the token isn't needed and wasn't saved.")
		return 0
	}
	path, err := enrollment.WriteToken(cfg, *token, *serverURL, *anonKey)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "enroll: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "Saved the enrollment token to %s; the agent enrolls when its service starts.\n", path)
	return 0
}
