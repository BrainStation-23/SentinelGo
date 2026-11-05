package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/localadmin"
)

// LocalAdminCommand is `sentinelgo local-admin expire <grant_id>`, run by
// the backup OS task at a grant's end time (#388), and
// `sentinelgo local-admin status` for support.
const LocalAdminCommand = "local-admin"

// expireWaitMax is how long expire waits for a grant that isn't due yet
// (the OS task can fire a little early).
const expireWaitMax = 5 * time.Minute

// localAdminManager and sleep are seams for tests.
var (
	localAdminManager = func(dir string) (localAdminExpirer, error) { return localadmin.ForConfigDir(dir) }
	cliSleep          = func(ctx context.Context, d time.Duration) {
		select {
		case <-ctx.Done():
		case <-time.After(d):
		}
	}
)

type localAdminExpirer interface {
	Expire(ctx context.Context, grantID string) (string, error)
}

// RunLocalAdmin runs the local-admin subcommands and returns the exit code.
func RunLocalAdmin(args []string, stdout, stderr io.Writer) int {
	usage := func() int {
		_, _ = fmt.Fprintln(stderr, "usage: sentinelgo local-admin expire <grant_id> [-config PATH]\n       sentinelgo local-admin status [-config PATH]")
		return 2
	}
	if len(args) == 0 {
		return usage()
	}
	fs := flag.NewFlagSet("local-admin", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "config.json of the install (default: the standard path)")
	sub, rest := args[0], args[1:]
	var grantID string
	if sub == "expire" {
		if len(rest) == 0 {
			return usage()
		}
		grantID, rest = rest[0], rest[1:]
		if !localadmin.ValidGrantID(grantID) {
			_, _ = fmt.Fprintln(stderr, "local-admin: not a grant id")
			return 2
		}
	}
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	path := *cfgPath
	if path == "" {
		path = config.GetDefaultConfigPath()
	}
	dir := filepath.Dir(path)

	switch sub {
	case "status":
		grants := localadmin.Report(localadmin.StorePath(dir), time.Now())
		b, _ := json.MarshalIndent(grants, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(b))
		return 0
	case "expire":
		return expireGrant(dir, grantID, stdout, stderr)
	}
	return usage()
}

func expireGrant(dir, grantID string, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), expireWaitMax+2*time.Minute)
	defer cancel()
	m, err := localAdminManager(dir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "local-admin: %v\n", err)
		return 1
	}
	// The task fires at the end time; if this clock runs a little ahead of
	// the one that set it, wait for the grant to be due.
	for _, g := range localadmin.Report(localadmin.StorePath(dir), time.Now()) {
		if g.GrantID == grantID && g.State != localadmin.GrantRemoved {
			if wait := time.Until(g.ExpiresAt); wait > 0 && wait <= expireWaitMax {
				cliSleep(ctx, wait+time.Second)
			}
		}
	}
	state, err := m.Expire(ctx, grantID)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "local-admin: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "grant %s: %s\n", grantID, state)
	if state == localadmin.GrantFailed {
		return 1
	}
	return 0
}
