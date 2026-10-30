//go:build linux

package session

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/ipc"
)

// The helper runs as a systemd user service in each graphical session,
// started by graphical-session.target. An XDG autostart entry covers
// desktops without that target; when both start one, the helper's
// single-instance lock keeps one. The session's DISPLAY / WAYLAND_DISPLAY
// reach the unit through the user manager's environment, which desktops
// import with `dbus-update-activation-environment --systemd` (GNOME and KDE
// do so on login).
const unitName = "sentinelgo-dlp.service"

// autostartFile is the XDG autostart fallback (a var for tests).
var autostartFile = "/etc/xdg/autostart/sentinelgo-dlp.desktop"

// unitDirs are tried in order for the global user unit.
var unitDirs = []string{"/usr/lib/systemd/user", "/etc/systemd/user"}

// runCmd runs a system tool by absolute path (never through PATH). Replaced
// in tests.
var runCmd = func(name string, args ...string) ([]byte, error) {
	path, err := sysTool(name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, path, args...).CombinedOutput() // #nosec G204 -- fixed system tools; arguments are unit names and local user names
}

// CleanupHelpers removes the helper definitions and stops helpers, for
// `sentinelgo -uninstall`: the running service normally does this when it
// stops, but not after an abrupt exit.
func CleanupHelpers() error {
	a := &systemdAgents{}
	if users, err := a.Users(); err == nil {
		for _, u := range users {
			_ = a.Stop(u)
		}
	}
	for _, dir := range unitDirs {
		if err := os.Remove(filepath.Join(dir, unitName)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return a.Uninstall()
}

// New returns the Linux supervisor.
func New(sink channel.EventSink) Service {
	exe, err := os.Executable()
	if err != nil {
		return &manualSupervisor{Hub: NewHub(ipc.DefaultAddress, sink)}
	}
	s := newAgentSupervisor(NewHub(ipc.DefaultAddress, sink), &systemdAgents{exe: exe})
	s.label = labelUser
	return s
}

// labelUser names a user for the status: the name, and the uid as the
// session id (what the hub reports for a connected helper).
func labelUser(name string) (string, string) {
	if u, err := user.Lookup(name); err == nil {
		return name, u.Uid
	}
	return name, ""
}

type systemdAgents struct {
	exe      string
	unitPath string
}

func unitFile(exe string) string {
	return fmt.Sprintf(`[Unit]
Description=SentinelGo DLP session helper
PartOf=graphical-session.target
After=graphical-session.target

[Service]
ExecStart=%q dlp-session
Restart=on-failure
RestartSec=5

[Install]
WantedBy=graphical-session.target
`, exe)
}

func desktopFile(exe string) string {
	return fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=SentinelGo DLP
Comment=Data loss prevention session helper
Exec=%q dlp-session
NoDisplay=true
X-GNOME-Autostart-enabled=true
`, exe)
}

func (a *systemdAgents) Install() error {
	a.unitPath = ""
	for _, dir := range unitDirs {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			a.unitPath = filepath.Join(dir, unitName)
			break
		}
	}
	if a.unitPath == "" {
		a.unitPath = filepath.Join(unitDirs[1], unitName)
		if err := os.MkdirAll(unitDirs[1], 0o755); err != nil { // #nosec G301 -- systemd's own config dir
			return err
		}
	}
	if err := writeIfChanged(a.unitPath, unitFile(a.exe)); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(autostartFile), 0o755); err == nil { // #nosec G301 -- XDG config dir
		if err := writeIfChanged(autostartFile, desktopFile(a.exe)); err != nil {
			return err
		}
	}
	// Without systemd the XDG autostart entry alone starts helpers at login,
	// so this isn't fatal.
	if out, err := runCmd("systemctl", "--global", "enable", unitName); err != nil {
		log.Printf("DLP: systemctl --global enable (XDG autostart still applies): %v: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

func (a *systemdAgents) Uninstall() error {
	_, _ = runCmd("systemctl", "--global", "disable", unitName)
	for _, p := range []string{a.unitPath, autostartFile} {
		if p == "" {
			continue
		}
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// Users lists users with a graphical (X11 or Wayland) login session. A user
// gets one helper even with two graphical sessions at once: systemd user
// units are per user. That rare case is a known limitation.
func (a *systemdAgents) Users() ([]string, error) {
	out, err := runCmd("loginctl", "list-sessions", "--no-legend")
	if err != nil {
		return nil, fmt.Errorf("loginctl list-sessions: %v", err)
	}
	seen := map[string]bool{}
	var users []string
	for _, id := range sessionIDs(out) {
		props, err := runCmd("loginctl", "show-session", id, "-p", "Name", "-p", "Type", "-p", "Class")
		if err != nil {
			continue // the session ended meanwhile
		}
		if name, ok := graphicalUser(props); ok && !seen[name] {
			seen[name] = true
			users = append(users, name)
		}
	}
	return users, nil
}

// sessionIDs takes the first column of `loginctl list-sessions --no-legend`.
func sessionIDs(out []byte) []string {
	var ids []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) > 0 {
			ids = append(ids, f[0])
		}
	}
	return ids
}

// graphicalUser reads `loginctl show-session -p Name -p Type -p Class`
// output: a user session of type x11 or wayland.
func graphicalUser(props []byte) (string, bool) {
	kv := map[string]string{}
	for _, line := range strings.Split(string(props), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			kv[k] = v
		}
	}
	if kv["Class"] != "user" || (kv["Type"] != "x11" && kv["Type"] != "wayland") || kv["Name"] == "" {
		return "", false
	}
	return kv["Name"], true
}

func (a *systemdAgents) Start(user string, restart bool) error {
	m := user + "@"
	_, _ = runCmd("systemctl", "--user", "-M", m, "daemon-reload") // see a newly installed unit
	verb := "start"
	if restart {
		verb = "restart"
	}
	if out, err := runCmd("systemctl", "--user", "-M", m, verb, unitName); err != nil {
		return fmt.Errorf("systemctl --user -M %s %s: %v: %s", m, verb, err, bytes.TrimSpace(out))
	}
	return nil
}

func (a *systemdAgents) Stop(user string) error {
	if out, err := runCmd("systemctl", "--user", "-M", user+"@", "stop", unitName); err != nil {
		return fmt.Errorf("systemctl --user stop: %v: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// writeIfChanged writes content to path (0644) unless it already holds it.
func writeIfChanged(path, content string) error {
	if old, err := os.ReadFile(path); err == nil && string(old) == content { // #nosec G304 -- fixed system paths
		return nil
	}
	return os.WriteFile(path, []byte(content), 0o644) // #nosec G306 -- unit and autostart files must be world-readable
}
