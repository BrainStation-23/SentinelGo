package native

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"sentinelgo/internal/config"
	"sentinelgo/internal/taskstore"
)

// Notification levels the console may send; anything else is shown as info.
const (
	NotifyLevelInfo     = "info"
	NotifyLevelWarning  = "warning"
	NotifyLevelCritical = "critical"
)

// Payload limits, in runes. Longer text is cut, not refused.
const (
	maxNotifyTitle   = 64
	maxNotifyMessage = 256
)

// notifyWait bounds how long the task waits for the sessions to answer.
var notifyWait = 20 * time.Second

// DesktopNotification is an admin's message for the signed-in users.
type DesktopNotification struct {
	Title   string
	Message string
	Level   string // NotifyLevelInfo, NotifyLevelWarning or NotifyLevelCritical
}

// NotifyResult is one session's outcome: Err is "" when it was shown.
type NotifyResult struct {
	User string
	Err  string
}

// UserNotifier shows n in every session with a connected helper and returns
// each one's result, plus the signed-in users without a connected helper
// (with why, e.g. "alice (start_failed: …)"). The service installs it.
type UserNotifier func(ctx context.Context, n DesktopNotification) (results []NotifyResult, unreached []string)

var (
	userNotifierMu sync.RWMutex
	userNotifier   UserNotifier
)

// SetUserNotifier installs (or with nil removes) the hook notify-user calls.
func SetUserNotifier(f UserNotifier) {
	userNotifierMu.Lock()
	defer userNotifierMu.Unlock()
	userNotifier = f
}

// errNoUser is the result when nobody is signed in: the message isn't kept
// for later, because a reboot warning shown hours late is wrong.
var errNoUser = errors.New("no user is signed in; nothing was shown")

// notifyUserHandler shows an admin's desktop notification to whoever is
// signed in. The service can't show one itself (it runs in session 0 or as
// root), so the session helpers show it. The text is never logged.
type notifyUserHandler struct{}

func init() { Register(&notifyUserHandler{}) }

// Slugs: the console's slugs allow hyphens only (#288); the underscore form
// matches the other native tasks' contract names.
func (h *notifyUserHandler) Slugs() []string { return []string{"notify-user", "notify_user"} }

func (h *notifyUserHandler) Run(ctx context.Context, _ *config.Config, task taskstore.Task) (string, error) {
	n, err := parseNotification(task.Payload)
	if err != nil {
		return "", err
	}
	userNotifierMu.RLock()
	f := userNotifier
	userNotifierMu.RUnlock()
	if f == nil {
		return "", errors.New("desktop notifications are unavailable: the session helper service isn't running")
	}
	ctx, cancel := context.WithTimeout(ctx, notifyWait)
	defer cancel()
	results, unreached := f(ctx, n)
	return notifyNote(results, unreached)
}

// parseNotification validates the payload: title and message are required
// strings, cut to their limits; an unknown level is info; other keys are
// ignored.
func parseNotification(p map[string]interface{}) (DesktopNotification, error) {
	title, err := requiredText(p, "title", maxNotifyTitle)
	if err != nil {
		return DesktopNotification{}, err
	}
	message, err := requiredText(p, "message", maxNotifyMessage)
	if err != nil {
		return DesktopNotification{}, err
	}
	level, _ := p["level"].(string)
	switch level = strings.ToLower(strings.TrimSpace(level)); level {
	case NotifyLevelWarning, NotifyLevelCritical:
	default:
		level = NotifyLevelInfo
	}
	return DesktopNotification{Title: title, Message: message, Level: level}, nil
}

func requiredText(p map[string]interface{}, key string, limit int) (string, error) {
	v, ok := p[key]
	if !ok || v == nil {
		return "", fmt.Errorf("notify-user: payload.%s is required", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("notify-user: payload.%s must be a string", key)
	}
	s = strings.TrimSpace(strings.ToValidUTF8(s, ""))
	if s == "" {
		return "", fmt.Errorf("notify-user: payload.%s is empty", key)
	}
	if utf8.RuneCountInString(s) > limit {
		s = string([]rune(s)[:limit-1]) + "…"
	}
	return s, nil
}

// notifyNote turns the sessions' results into the task's note: success when
// at least one session showed it.
func notifyNote(results []NotifyResult, unreached []string) (string, error) {
	var shown, failed []string
	for _, r := range results {
		if r.Err == "" {
			shown = append(shown, r.User)
		} else {
			failed = append(failed, r.User+": "+r.Err)
		}
	}
	if len(shown) == 0 {
		switch {
		case len(failed) > 0:
			return "", fmt.Errorf("nothing was shown: %s", strings.Join(append(failed, notConnected(unreached)...), "; "))
		case len(unreached) > 0:
			return "", fmt.Errorf("nothing was shown: %s", strings.Join(notConnected(unreached), "; "))
		default:
			return "", errNoUser
		}
	}
	note := fmt.Sprintf("Shown to %d %s (%s)", len(shown), plural(len(shown), "session", "sessions"), strings.Join(shown, ", "))
	if len(failed) > 0 {
		note += "; not shown to " + strings.Join(failed, "; ")
	}
	if len(unreached) > 0 {
		note += "; " + strings.Join(notConnected(unreached), "; ")
	}
	return note, nil
}

func notConnected(users []string) []string {
	if len(users) == 0 {
		return nil
	}
	return []string{"no session helper connected for " + strings.Join(users, ", ")}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
