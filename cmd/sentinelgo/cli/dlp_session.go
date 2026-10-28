package cli

import (
	"context"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"sentinelgo/internal/config"
	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/channel/clipboard"
	"sentinelgo/internal/dlp/ipc"
	"sentinelgo/internal/dlp/session"
)

// DLPSessionCommand is the hidden subcommand the service launches in each
// interactive user session.
const DLPSessionCommand = "dlp-session"

// maxHelperLogBytes is where the helper log is rotated (one old copy kept).
const maxHelperLogBytes = 5 << 20

// RunDLPSession runs the per-user DLP session helper until the service tells
// it to stop or it is signalled. It deliberately takes no process lock and
// reads no config.json (it holds no credentials), and logs to a per-user
// file. Clipboard content is never logged.
func RunDLPSession() int {
	if f := openHelperLog(); f != nil {
		defer func() { _ = f.Close() }()
		log.SetOutput(f)
	}
	log.Printf("DLP helper %s starting (pid %d)", config.Version, os.Getpid())

	// One helper per user session: a systemd unit and an XDG autostart entry
	// (or a manual run) may both start one.
	release, ok, err := session.AcquireHelperLock()
	switch {
	case err != nil:
		log.Printf("DLP helper: single-instance lock unavailable, continuing: %v", err)
	case !ok:
		log.Printf("DLP helper: another helper runs in this session; exiting")
		return 0
	default:
		defer release()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = session.RunHelper(ctx, session.HelperOptions{
		Addr:     ipc.DefaultAddress,
		Version:  config.Version,
		Channels: []channel.Channel{clipboard.New()},
	})
	if err != nil {
		log.Printf("DLP helper stopped: %v", err)
		return 1
	}
	log.Printf("DLP helper exiting")
	return 0
}

// openHelperLog opens the per-user helper log (rotating it past
// maxHelperLogBytes), or returns nil to keep logging to stderr.
func openHelperLog() io.WriteCloser {
	dir, err := os.UserCacheDir()
	if err != nil {
		return nil
	}
	dir = filepath.Join(dir, "SentinelGo")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil
	}
	path := filepath.Join(dir, "dlp-session.log")
	if fi, err := os.Stat(path); err == nil && fi.Size() > maxHelperLogBytes {
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- path is under the user's own cache dir
	if err != nil {
		return nil
	}
	return f
}
