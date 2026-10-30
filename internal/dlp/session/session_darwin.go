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

// runCmd runs a system tool by absolute path (never through PATH). Replaced
// in tests.
var runCmd = func(name string, args ...string) ([]byte, error) {
	path, err := sysTool(name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, path, args...).CombinedOutput() // #nosec G204 -- fixed system tools; arguments are uids and the fixed label/path
}

// CleanupHelpers unloads the LaunchAgent and removes its plist, for
// `sentinelgo -uninstall`: the running service normally does this when it
// stops, but not after an abrupt exit.
func CleanupHelpers() error {
	a := &launchdAgents{}
	if uids, err := a.Users(); err == nil {
		for _, uid := range uids {
			_ = a.Stop(uid)
		}
	}
	return a.Uninstall()
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
func New(sink channel.EventSink) Service {
	exe, err := os.Executable()
	if err != nil {
		return &manualSupervisor{Hub: NewHub(ipc.DefaultAddress, sink)}
	}
	s := newAgentSupervisor(NewHub(ipc.DefaultAddress, sink), &launchdAgents{exe: exe})
	s.label = labelUID
	return s
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
	if err := userExecutable(a.exe); err != nil {
		return err
	}
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

// Start makes sure the helper runs in uid's GUI session: a job that isn't
// loaded is bootstrapped, one that is loaded but not running (it exited
// cleanly, which launchd doesn't restart) is kickstarted, and a running one
// is replaced only with restart.
func (a *launchdAgents) Start(uid string, restart bool) error {
	domain := "gui/" + uid
	target := domain + "/" + agentLabel
	out, err := runCmd("launchctl", "print", target)
	if err != nil {
		return a.bootstrap(domain)
	}
	if !jobRunning(out) {
		if out, err := runCmd("launchctl", "kickstart", target); err != nil {
			return fmt.Errorf("launchctl kickstart %s: %v: %s", target, err, bytes.TrimSpace(out))
		}
		return nil
	}
	if !restart {
		return nil
	}
	out, err = runCmd("launchctl", "kickstart", "-k", target)
	if err == nil {
		return nil
	}
	// kickstart -k has been seen to hang when root runs it against a GUI
	// domain. Replace the job instead: unload it (stopping the old helper)
	// and load it again, which starts the current binary (RunAtLoad).
	kerr := fmt.Errorf("launchctl kickstart -k %s: %v: %s", target, err, bytes.TrimSpace(out))
	if err := a.Stop(uid); err != nil {
		return fmt.Errorf("%v; then %v", kerr, err)
	}
	if err := a.bootstrap(domain); err != nil {
		return fmt.Errorf("%v; then %v", kerr, err)
	}
	return nil
}

// bootstrap loads the job in domain; RunAtLoad starts the current binary.
func (a *launchdAgents) bootstrap(domain string) error {
	if out, err := runCmd("launchctl", "bootstrap", domain, agentPlist); err != nil {
		return fmt.Errorf("launchctl bootstrap %s: %v: %s", domain, err, bytes.TrimSpace(out))
	}
	return nil
}

// jobRunning reads `launchctl print` output: the job's own top-level
// "state = running" (nested blocks are indented further).
func jobRunning(out []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "\tstate = ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "\tstate = ")) == "running"
		}
	}
	return false
}

// labelUID names a uid for the status: the account name, and the uid as the
// session id (what the hub reports for a connected helper).
func labelUID(uid string) (string, string) {
	if u, err := user.LookupId(uid); err == nil {
		return u.Username, uid
	}
	return uid, uid
}

func (a *launchdAgents) Stop(uid string) error {
	out, err := runCmd("launchctl", "bootout", "gui/"+uid+"/"+agentLabel)
	if err != nil && !bytes.Contains(out, []byte("No such process")) {
		return fmt.Errorf("launchctl bootout: %v: %s", err, bytes.TrimSpace(out))
	}
	return nil
}
