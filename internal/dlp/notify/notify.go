// Package notify shows the user a desktop notification when a DLP channel
// blocks content. It runs in the session helper. Notifications go through
// the desktop's own tools (PowerShell toast on Windows, osascript on macOS,
// notify-send on Linux) with the text passed in environment variables or as
// plain arguments, never inside a script or through a shell. Sending is
// asynchronous and rate-limited; a failure to notify never affects
// enforcement.
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

// New returns a Notifier for this platform.
func New() *Notifier { return &Notifier{now: time.Now, send: platformSend} }

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
