//go:build darwin

package session

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"time"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/ipc"
)

// The helper is a LaunchAgent loaded in each user's Aqua (GUI) session:
// launchd starts it at login and restarts it if it crashes. It isn't
// restarted after a clean exit, which is how it leaves when the service
// tells it to stop. SSH-only sessions never load it (LimitLoadToSessionType).
const agentLabel = "com.sentinelgo.dlp"

// agentPlist is the LaunchAgent definition (a var for tests).
var agentPlist = "/Library/LaunchAgents/com.sentinelgo.dlp.plist"

// runCmd runs a system tool. Replaced in tests.
var runCmd = func(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput() // #nosec G204 -- fixed tool names; arguments are uids and the fixed label/path
}

// lookupUID maps a user name to its uid. Replaced in tests.
var lookupUID = func(name string) (string, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return "", err
	}
	return u.Uid, nil
}

// New returns the macOS supervisor.
func New(sink channel.EventSink) Supervisor {
	exe, err := os.Executable()
	if err != nil {
		return &manualSupervisor{Hub: NewHub(ipc.DefaultAddress, sink)}
	}
	return newAgentSupervisor(NewHub(ipc.DefaultAddress, sink), &launchdAgents{exe: exe})
}

type launchdAgents struct{ exe string }

func plistFor(exe string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>dlp-session</string>
	</array>
	<key>LimitLoadToSessionType</key>
	<string>Aqua</string>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
`, agentLabel, xmlEscape(exe))
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func (a *launchdAgents) Install() error {
	content := plistFor(a.exe)
	if old, err := os.ReadFile(agentPlist); err == nil && string(old) == content { // #nosec G304 -- fixed system path
		return nil
	}
	return os.WriteFile(agentPlist, []byte(content), 0o644) // #nosec G306 -- launchd requires LaunchAgents to be world-readable
}

func (a *launchdAgents) Uninstall() error {
	if err := os.Remove(agentPlist); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Users returns the uids of users logged in at the console (GUI sessions,
// including fast user switching); SSH logins are on ttys, not "console".
func (a *launchdAgents) Users() ([]string, error) {
	out, err := runCmd("who")
	if err != nil {
		return nil, fmt.Errorf("who: %v", err)
	}
	seen := map[string]bool{}
	var uids []string
	for _, name := range consoleUsers(out) {
		uid, err := lookupUID(name)
		if err != nil || seen[uid] {
			continue
		}
		seen[uid] = true
		uids = append(uids, uid)
	}
	return uids, nil
}

// consoleUsers picks the users on "console" from `who` output.
func consoleUsers(out []byte) []string {
	var users []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) >= 2 && f[1] == "console" {
			users = append(users, f[0])
		}
	}
	return users
}

func (a *launchdAgents) Start(uid string, restart bool) error {
	domain := "gui/" + uid
	if _, err := runCmd("launchctl", "print", domain+"/"+agentLabel); err != nil {
		if out, err := runCmd("launchctl", "bootstrap", domain, agentPlist); err != nil {
			return fmt.Errorf("launchctl bootstrap %s: %v: %s", domain, err, bytes.TrimSpace(out))
		}
		return nil // just loaded: RunAtLoad starts the current binary
	}
	if restart {
		if out, err := runCmd("launchctl", "kickstart", "-k", domain+"/"+agentLabel); err != nil {
			return fmt.Errorf("launchctl kickstart %s: %v: %s", domain, err, bytes.TrimSpace(out))
		}
	}
	return nil
}

func (a *launchdAgents) Stop(uid string) error {
	out, err := runCmd("launchctl", "bootout", "gui/"+uid+"/"+agentLabel)
	if err != nil && !bytes.Contains(out, []byte("No such process")) {
		return fmt.Errorf("launchctl bootout: %v: %s", err, bytes.TrimSpace(out))
	}
	return nil
}
