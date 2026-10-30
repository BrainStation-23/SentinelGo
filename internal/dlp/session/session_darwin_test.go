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
	prevRun, prevPlist, prevLookup, prevExec := runCmd, agentPlist, lookupUID, userExecutable
	agentPlist = filepath.Join(t.TempDir(), agentLabel+".plist")
	userExecutable = func(string) error { return nil }
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
		case len(args) > 1 && args[0] == "print":
			return []byte(printRunning), nil
		}
		return nil, nil
	}
	t.Cleanup(func() { runCmd, agentPlist, lookupUID, userExecutable = prevRun, prevPlist, prevLookup, prevExec })

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

// launchctl print output (abridged) for a running and a stopped job.
const (
	printRunning = "gui/501/com.sentinelgo.dlp = {\n\tactive count = 1\n\tpath = /Library/LaunchAgents/com.sentinelgo.dlp.plist\n\tstate = running\n\n\tendpoints = {\n\t\t\"x\" = {\n\t\t\tstate = active\n\t\t}\n\t}\n\tpid = 4242\n}\n"
	printStopped = "gui/501/com.sentinelgo.dlp = {\n\tactive count = 0\n\tpath = /Library/LaunchAgents/com.sentinelgo.dlp.plist\n\tstate = not running\n\n\tendpoints = {\n\t\t\"x\" = {\n\t\t\tstate = running\n\t\t}\n\t}\n\truns = 1\n\tlast exit code = 0\n}\n"
)

func TestJobRunning(t *testing.T) {
	if !jobRunning([]byte(printRunning)) {
		t.Error("running job reported as not running")
	}
	if jobRunning([]byte(printStopped)) {
		t.Error("stopped job reported as running (nested state must not count)")
	}
	if jobRunning(nil) {
		t.Error("empty output reported as running")
	}
}

// Start makes sure the helper runs, not only that its job is loaded (#299).
func TestLaunchdAgentsStart(t *testing.T) {
	const target = "gui/501/" + agentLabel
	bootstrap := "launchctl bootstrap gui/501 "
	for _, tc := range []struct {
		name    string
		print   string // "" = not loaded
		restart bool
		fail    string // a call prefix that fails
		want    []string
		wantErr bool
	}{
		{name: "not loaded: bootstrap", restart: false, want: []string{"launchctl print " + target, bootstrap}},
		{name: "loaded, not running: kickstart without -k", print: printStopped, want: []string{"launchctl print " + target, "launchctl kickstart " + target}},
		{name: "loaded, not running, restart: kickstart", print: printStopped, restart: true, want: []string{"launchctl print " + target, "launchctl kickstart " + target}},
		{name: "running, no restart: nothing", print: printRunning, want: []string{"launchctl print " + target}},
		{name: "running, restart: kickstart -k", print: printRunning, restart: true, want: []string{"launchctl print " + target, "launchctl kickstart -k " + target}},
		{name: "kickstart fails: error", print: printStopped, fail: "launchctl kickstart", want: []string{"launchctl print " + target, "launchctl kickstart " + target}, wantErr: true},
		{name: "kickstart -k fails: bootout then bootstrap", print: printRunning, restart: true, fail: "launchctl kickstart -k",
			want: []string{"launchctl print " + target, "launchctl kickstart -k " + target, "launchctl bootout " + target, bootstrap}},
		{name: "kickstart -k and bootstrap fail: error", print: printRunning, restart: true, fail: "launchctl b",
			want: []string{"launchctl print " + target, "launchctl kickstart -k " + target, "launchctl bootout " + target}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			prevRun := runCmd
			t.Cleanup(func() { runCmd = prevRun })
			runCmd = func(name string, args ...string) ([]byte, error) {
				call := name + " " + strings.Join(args, " ")
				calls = append(calls, call)
				if args[0] == "print" {
					if tc.print == "" {
						return []byte("Could not find service"), errors.New("exit status 113")
					}
					return []byte(tc.print), nil
				}
				if tc.fail == "launchctl kickstart -k" && args[0] == "kickstart" && len(args) > 1 && args[1] == "-k" {
					return nil, errors.New("signal: killed")
				}
				if tc.fail == "launchctl b" && (strings.HasPrefix(call, "launchctl kickstart -k") || args[0] == "bootstrap") {
					return nil, errors.New("exit status 5")
				}
				if tc.fail == "launchctl kickstart" && args[0] == "kickstart" {
					return nil, errors.New("exit status 5")
				}
				return nil, nil
			}
			err := (&launchdAgents{}).Start("501", tc.restart)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Start err = %v, wantErr %v", err, tc.wantErr)
			}
			if len(calls) < len(tc.want) {
				t.Fatalf("calls = %v, want %v", calls, tc.want)
			}
			for i, w := range tc.want {
				if !strings.HasPrefix(calls[i], w) {
					t.Errorf("call %d = %q, want %q (all: %v)", i, calls[i], w, calls)
				}
			}
			if len(calls) != len(tc.want) && !tc.wantErr {
				t.Errorf("calls = %v, want %v", calls, tc.want)
			}
		})
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

func TestLaunchdAgents_InstallNotExecutable(t *testing.T) {
	prevPlist, prevExec := agentPlist, userExecutable
	agentPlist = filepath.Join(t.TempDir(), agentLabel+".plist")
	userExecutable = func(string) error { return errors.New("not accessible") }
	t.Cleanup(func() { agentPlist, userExecutable = prevPlist, prevExec })

	a := &launchdAgents{exe: "/opt/sentinelgo/sentinelgo"}
	if err := a.Install(); err == nil {
		t.Fatal("Install = nil, want the permission error")
	}
	if _, err := os.Stat(agentPlist); !os.IsNotExist(err) {
		t.Errorf("plist written although no user can run the binary (%v)", err)
	}
}
