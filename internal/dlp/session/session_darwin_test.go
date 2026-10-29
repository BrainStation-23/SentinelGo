package session

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestConsoleUsers(t *testing.T) {
	out := []byte("alice    console  Oct 28 09:12\nalice    ttys000  Oct 28 09:13\nbob      console  Oct 28 10:01\ncarol    ttys001  Oct 28 11:00 (10.0.0.5)\n")
	if got := consoleUsers(out); !slices.Equal(got, []string{"alice", "bob"}) {
		t.Errorf("consoleUsers = %v, want the GUI logins only", got)
	}
}

func TestLaunchdAgents(t *testing.T) {
	var calls []string
	loaded := map[string]bool{"gui/502/" + agentLabel: true}
	prevRun, prevPlist, prevLookup := runCmd, agentPlist, lookupUID
	agentPlist = filepath.Join(t.TempDir(), agentLabel+".plist")
	lookupUID = func(name string) (string, error) {
		return map[string]string{"alice": "501", "bob": "502"}[name], nil
	}
	runCmd = func(name string, args ...string) ([]byte, error) {
		call := name + " " + strings.Join(args, " ")
		calls = append(calls, call)
		switch {
		case name == "who":
			return []byte("alice console Oct 28 09:12\nbob console Oct 28 10:01\nbob ttys000 Oct 28 10:02\n"), nil
		case len(args) > 1 && args[0] == "print" && !loaded[args[1]]:
			return nil, errors.New("not loaded")
		}
		return nil, nil
	}
	t.Cleanup(func() { runCmd, agentPlist, lookupUID = prevRun, prevPlist, prevLookup })

	a := &launchdAgents{exe: "/opt/sentinelgo/sentinelgo"}
	if err := a.Install(); err != nil {
		t.Fatal(err)
	}
	plist, _ := os.ReadFile(agentPlist)
	for _, want := range []string{"<string>com.sentinelgo.dlp</string>", "<string>/opt/sentinelgo/sentinelgo</string>", "<string>dlp-session</string>", "<string>Aqua</string>", "<key>SuccessfulExit</key>"} {
		if !strings.Contains(string(plist), want) {
			t.Errorf("plist lacks %s", want)
		}
	}
	uids, err := a.Users()
	if err != nil || !slices.Equal(uids, []string{"501", "502"}) {
		t.Fatalf("Users = %v, %v", uids, err)
	}
	if err := a.Start("501", true); err != nil { // not loaded: bootstrap
		t.Fatal(err)
	}
	if err := a.Start("502", true); err != nil { // loaded: kickstart -k for the new binary
		t.Fatal(err)
	}
	if err := a.Stop("502"); err != nil {
		t.Fatal(err)
	}
	if err := a.Uninstall(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"launchctl bootstrap gui/501 " + agentPlist,
		"launchctl kickstart -k gui/502/com.sentinelgo.dlp",
		"launchctl bootout gui/502/com.sentinelgo.dlp",
	} {
		if !slices.Contains(calls, want) {
			t.Errorf("missing %q in %v", want, calls)
		}
	}
	if _, err := os.Stat(agentPlist); !os.IsNotExist(err) {
		t.Error("plist left after Uninstall")
	}
}

func FuzzConsoleUsers(f *testing.F) {
	f.Add([]byte("alice    console  Oct 28 09:12\nbob ttys000 Oct 28\n"))
	f.Add([]byte("console\n  console x\n"))
	f.Fuzz(func(t *testing.T, out []byte) {
		for _, u := range consoleUsers(out) {
			if u == "" || strings.ContainsAny(u, " \t\n") {
				t.Fatalf("bad user name %q", u)
			}
		}
	})
}
