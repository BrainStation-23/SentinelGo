// Package notify shows the user a desktop notification when a DLP channel
// blocks content, or when an admin sends one (the notify-user task). It runs
// in the session helper. Notifications go through
// the desktop's own tools (PowerShell toast on Windows, osascript on macOS,
// notify-send on Linux) with the text passed in environment variables or as
// plain arguments, never inside a script or through a shell. Sending is
// asynchronous and rate-limited for DLP (Notifier); a failure to notify never
// affects enforcement. An admin's message (Show) is never rate-limited.
package notify

import (
	"log"
	"sync"
	"time"
)

// MinInterval is the least time between two notifications.
const MinInterval = 10 * time.Second

// maxText bounds what is shown.
const maxText = 256

// Notifier sends rate-limited notifications.
type Notifier struct {
	mu   sync.Mutex
	last time.Time
	now  func() time.Time
	send func(title, body string) error
	wg   sync.WaitGroup
}

// Levels for Show. DLP notifications have none.
const (
	LevelInfo     = "info"
	LevelWarning  = "warning"
	LevelCritical = "critical"
)

// New returns a Notifier for this platform.
func New() *Notifier {
	return &Notifier{now: time.Now, send: func(title, body string) error { return platformSend(title, body, "") }}
}

// Show shows title and body at level (LevelInfo, LevelWarning or
// LevelCritical; anything else is LevelInfo) and waits for the desktop tool.
// Unlike Notifier it is not rate-limited: an admin's message must not be
// dropped. The error names the tool and its exit status, never the text.
func Show(title, body, level string) error {
	switch level {
	case LevelWarning, LevelCritical:
	default:
		level = LevelInfo
	}
	return platformSend(trim(title), trim(body), level)
}

// Notify shows title and body unless a notification went out less than
// MinInterval ago. It doesn't wait for the notification.
func (n *Notifier) Notify(title, body string) {
	n.mu.Lock()
	now := n.now()
	if !n.last.IsZero() && now.Sub(n.last) < MinInterval {
		n.mu.Unlock()
		return
	}
	n.last = now
	n.mu.Unlock()

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		if err := n.send(trim(title), trim(body)); err != nil {
			// Exec errors carry the tool and exit status, never its
			// arguments or environment, so no message text reaches the log.
			log.Printf("DLP helper: desktop notification failed: %v", err)
		}
	}()
}

// Wait waits for notifications in flight (tests, shutdown).
func (n *Notifier) Wait() { n.wg.Wait() }

func trim(s string) string {
	r := []rune(s)
	if len(r) > maxText {
		return string(r[:maxText-1]) + "…"
	}
	return s
}
