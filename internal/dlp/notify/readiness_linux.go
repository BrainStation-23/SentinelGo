//go:build linux

package notify

import (
	"context"
	"os"
	"os/exec"
	"time"

	"sentinelgo/internal/binpath"
)

// busTools ask the session bus, from fixed paths: busctl (systemd) first,
// else gdbus (GLib).
var busTools = []struct {
	path      string
	hasOwner  []string
	inhibited []string
}{
	{"/usr/bin/busctl",
		[]string{"--user", "call", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "NameHasOwner", "s", "org.freedesktop.Notifications"},
		[]string{"--user", "get-property", "org.freedesktop.Notifications", "/org/freedesktop/Notifications", "org.freedesktop.Notifications", "Inhibited"}},
	{"/usr/bin/gdbus",
		[]string{"call", "--session", "--dest", "org.freedesktop.DBus", "--object-path", "/org/freedesktop/DBus", "--method", "org.freedesktop.DBus.NameHasOwner", "org.freedesktop.Notifications"},
		[]string{"call", "--session", "--dest", "org.freedesktop.Notifications", "--object-path", "/org/freedesktop/Notifications", "--method", "org.freedesktop.DBus.Properties.Get", "org.freedesktop.Notifications", "Inhibited"}},
}

func run(ctx context.Context, path string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, path, args...).Output() // #nosec G204 -- fixed tool paths and arguments
	return string(out), err
}

// Readiness checks notify-send, the session bus's notification server, and
// Do Not Disturb (GNOME's show-banners, the server's Inhibited property).
func Readiness() (state, detail string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var s linuxSettings
	for _, p := range notifySendPaths {
		if _, err := os.Stat(p); err == nil {
			s.ToolFound = true
			break
		}
	}
	for _, t := range busTools {
		if _, err := os.Stat(t.path); err != nil {
			continue
		}
		if out, err := run(ctx, t.path, t.hasOwner...); err == nil {
			s.ServerOwned = parseBusctlBool(out)
		}
		if out, err := run(ctx, t.path, t.inhibited...); err == nil {
			s.Inhibited = parseBusctlBool(out)
		}
		break
	}
	if g, ok := binpath.Lookup("gsettings"); ok {
		if out, err := run(ctx, g, "get", "org.gnome.desktop.notifications", "show-banners"); err == nil {
			s.ShowBanners = out
		}
	}
	return linuxReadiness(s)
}
