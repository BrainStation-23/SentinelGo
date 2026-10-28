package session

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func fakeSystem(t *testing.T, sessions map[string]string) *[]string {
	t.Helper()
	var calls []string
	prevRun, prevDirs, prevAuto := runCmd, unitDirs, autostartFile
	dir := t.TempDir()
	unitDirs = []string{filepath.Join(dir, "lib-user"), filepath.Join(dir, "etc-user")}
	autostartFile = filepath.Join(dir, "autostart", "sentinelgo-dlp.desktop")
	runCmd = func(name string, args ...string) ([]byte, error) {
		call := name + " " + strings.Join(args, " ")
		calls = append(calls, call)
		switch {
		case strings.HasPrefix(call, "loginctl list-sessions"):
			var b strings.Builder
			for id := range sessions {
				b.WriteString("    " + id + " 1000 someone seat0 tty2\n")
			}
			return []byte(b.String()), nil
		case strings.HasPrefix(call, "loginctl show-session"):
			if p, ok := sessions[args[1]]; ok {
				return []byte(p), nil
			}
			return nil, errors.New("no such session")
		}
		return nil, nil
	}
	t.Cleanup(func() { runCmd, unitDirs, autostartFile = prevRun, prevDirs, prevAuto })
	return &calls
}

func TestSystemdAgents_Users(t *testing.T) {
	fakeSystem(t, map[string]string{
		"2":  "Name=alice\nType=wayland\nClass=user\n",
		"3":  "Name=bob\nType=x11\nClass=user\n",
		"4":  "Name=carol\nType=tty\nClass=user\n",      // ssh / console: no clipboard
		"5":  "Name=gdm\nType=wayland\nClass=greeter\n", // login screen
		"6":  "Name=alice\nType=x11\nClass=user\n",      // second session, same user
		"c1": "Name=root\nType=unspecified\nClass=user\n",
	})
	a := &systemdAgents{exe: "/opt/sentinelgo/sentinelgo"}
	users, err := a.Users()
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(users)
	if !slices.Equal(users, []string{"alice", "bob"}) {
		t.Errorf("users = %v, want the graphical ones once each", users)
	}
}

func TestSystemdAgents_InstallStartStopUninstall(t *testing.T) {
	calls := fakeSystem(t, nil)
	a := &systemdAgents{exe: "/opt/sentinelgo/sentinelgo"}
	if err := os.MkdirAll(unitDirs[0], 0o755); err != nil {
		t.Fatal(err)
	}
	if err := a.Install(); err != nil {
		t.Fatal(err)
	}
	unit, err := os.ReadFile(filepath.Join(unitDirs[0], unitName))
	if err != nil || !strings.Contains(string(unit), `ExecStart="/opt/sentinelgo/sentinelgo" dlp-session`) ||
		!strings.Contains(string(unit), "WantedBy=graphical-session.target") {
		t.Fatalf("unit = %s (%v)", unit, err)
	}
	if desk, err := os.ReadFile(autostartFile); err != nil || !strings.Contains(string(desk), "dlp-session") {
		t.Errorf("autostart = %s (%v)", desk, err)
	}
	if err := a.Start("alice", true); err != nil {
		t.Fatal(err)
	}
	if err := a.Stop("alice"); err != nil {
		t.Fatal(err)
	}
	if err := a.Uninstall(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"systemctl --global enable sentinelgo-dlp.service",
		"systemctl --user -M alice@ restart sentinelgo-dlp.service",
		"systemctl --user -M alice@ stop sentinelgo-dlp.service",
		"systemctl --global disable sentinelgo-dlp.service",
	} {
		if !slices.Contains(*calls, want) {
			t.Errorf("missing call %q in %v", want, *calls)
		}
	}
	if _, err := os.Stat(autostartFile); !os.IsNotExist(err) {
		t.Error("autostart entry left after Uninstall")
	}
}
