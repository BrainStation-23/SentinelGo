package cli

import (
	"context"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/channel/clipboard"
	"sentinelgo/internal/dlp/ipc"
	"sentinelgo/internal/dlp/notify"
	"sentinelgo/internal/dlp/session"
)

// DLPSessionCommand is the hidden subcommand the service launches in each
// interactive user session.
const DLPSessionCommand = "dlp-session"

// maxHelperLogBytes is where the helper log is rotated (one old copy kept).
const maxHelperLogBytes = 5 << 20

// RunDLPSession runs the per-user session helper until the service tells it
// to stop or it is signalled. It enforces DLP when there is a policy and
// shows the admin's notifications (notify-user) either way. It deliberately takes no process lock and
// reads no config.json (it holds no credentials), and logs to a per-user
// file. Clipboard content is never logged.
func RunDLPSession() int {
	if f := openHelperLog(); f != nil {
		defer func() { _ = f.Close() }()
		log.SetOutput(f)
	}
	log.Printf("DLP helper %s starting (pid %d)", config.Version, os.Getpid())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// One helper per user session: a systemd unit and an XDG autostart entry
	// (or a manual run) may both start one. The second waits as a standby
	// and takes over if the first dies, so a crash isn't left unrecovered.
	release, err := waitForHelperLock(ctx)
	if err != nil {
		log.Printf("DLP helper: single-instance lock unavailable, continuing: %v", err)
	} else if release == nil {
		return 0 // stopped while on standby
	} else {
		defer release()
	}
	err = session.RunHelper(ctx, session.HelperOptions{
		Addr:     ipc.DefaultAddress,
		Version:  config.Version,
		Channels: []channel.Channel{clipboard.New()},
		Notify:   notify.Show,
	})
	if err != nil {
		log.Printf("DLP helper stopped: %v", err)
		return 1
	}
	log.Printf("DLP helper exiting")
	return 0
}

// helperLockRetry is how often a standby helper retries the lock.
var helperLockRetry = 5 * time.Second

// waitForHelperLock takes the session's helper lock, waiting as a standby
// while another helper holds it. It returns a nil release (and nil error)
// when ctx ends first.
func waitForHelperLock(ctx context.Context) (func(), error) {
	for logged := false; ; {
		release, ok, err := session.AcquireHelperLock()
		if err != nil || ok {
			return release, err
		}
		if !logged {
			log.Printf("DLP helper: another helper runs in this session; standing by")
			logged = true
		}
		select {
		case <-ctx.Done():
			return nil, nil
		case <-time.After(helperLockRetry):
		}
	}
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
