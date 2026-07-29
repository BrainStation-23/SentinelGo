//go:build linux

package prompt

import (
	"errors"
	"testing"
)

func fakeLookPath(available string) func(string) (string, error) {
	return func(name string) (string, error) {
		if name == available {
			return "/usr/bin/" + name, nil
		}
		return "", errors.New("not found")
	}
}

func TestLinuxPrompter_Available(t *testing.T) {
	cases := []struct {
		name      string
		available string
		want      bool
	}{
		{"zenity present", "zenity", true},
		{"kdialog present", "kdialog", true},
		{"neither present", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &LinuxPrompter{lookPath: fakeLookPath(tc.available)}
			if got := p.Available(); got != tc.want {
				t.Errorf("Available() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLinuxPrompter_Confirm_Zenity(t *testing.T) {
	cases := []struct {
		name     string
		exitCode int
		want     bool
	}{
		{"yes", 0, true},
		{"no", 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotArgs []string
			p := &LinuxPrompter{
				lookPath: fakeLookPath("zenity"),
				runCommand: func(name string, args ...string) (string, int, error) {
					gotArgs = append([]string{name}, args...)
					return "", tc.exitCode, nil
				},
			}
			got, err := p.Confirm("Title", "Message")
			if err != nil {
				t.Fatalf("Confirm() error = %v", err)
			}
			if got != tc.want {
				t.Errorf("Confirm() = %v, want %v", got, tc.want)
			}
			if gotArgs[0] != "zenity" || gotArgs[1] != "--question" {
				t.Errorf("command = %v, want zenity --question ...", gotArgs)
			}
		})
	}
}

func TestLinuxPrompter_Confirm_KdialogFallback(t *testing.T) {
	var gotArgs []string
	p := &LinuxPrompter{
		lookPath: fakeLookPath("kdialog"),
		runCommand: func(name string, args ...string) (string, int, error) {
			gotArgs = append([]string{name}, args...)
			return "", 0, nil
		},
	}
	got, err := p.Confirm("Title", "Message")
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if !got {
		t.Error("Confirm() = false, want true")
	}
	if gotArgs[0] != "kdialog" {
		t.Errorf("command = %v, want kdialog ...", gotArgs)
	}
}

func TestLinuxPrompter_Confirm_NoBackend(t *testing.T) {
	p := &LinuxPrompter{lookPath: fakeLookPath("")}
	if _, err := p.Confirm("Title", "Message"); !errors.Is(err, errNoDialogBackend) {
		t.Errorf("Confirm() error = %v, want errNoDialogBackend", err)
	}
}

func TestLinuxPrompter_Justify_Zenity(t *testing.T) {
	p := &LinuxPrompter{
		lookPath: fakeLookPath("zenity"),
		runCommand: func(name string, args ...string) (string, int, error) {
			return "the answer\n", 0, nil
		},
	}
	text, ok, err := p.Justify("Title", "Message")
	if err != nil {
		t.Fatalf("Justify() error = %v", err)
	}
	if !ok || text != "the answer" {
		t.Errorf("Justify() = (%q, %v), want (the answer, true)", text, ok)
	}
}

func TestLinuxPrompter_Justify_Cancelled(t *testing.T) {
	p := &LinuxPrompter{
		lookPath:   fakeLookPath("zenity"),
		runCommand: func(string, ...string) (string, int, error) { return "", 1, nil },
	}
	text, ok, err := p.Justify("Title", "Message")
	if err != nil {
		t.Fatalf("Justify() error = %v", err)
	}
	if ok || text != "" {
		t.Errorf("Justify() = (%q, %v), want (\"\", false) on cancel", text, ok)
	}
}

func TestLinuxPrompter_Justify_Kdialog(t *testing.T) {
	var gotArgs []string
	p := &LinuxPrompter{
		lookPath: fakeLookPath("kdialog"),
		runCommand: func(name string, args ...string) (string, int, error) {
			gotArgs = append([]string{name}, args...)
			return "kdialog answer\n", 0, nil
		},
	}
	text, ok, err := p.Justify("Title", "Message")
	if err != nil {
		t.Fatalf("Justify() error = %v", err)
	}
	if !ok || text != "kdialog answer" {
		t.Errorf("Justify() = (%q, %v), want (kdialog answer, true)", text, ok)
	}
	if gotArgs[0] != "kdialog" || gotArgs[2] != "--inputbox" {
		t.Errorf("command = %v", gotArgs)
	}
}

func TestLinuxPrompter_Notify(t *testing.T) {
	var called bool
	p := &LinuxPrompter{
		lookPath: fakeLookPath("zenity"),
		runCommand: func(name string, args ...string) (string, int, error) {
			called = true
			if name != "zenity" || args[0] != "--info" {
				t.Errorf("command = %s %v", name, args)
			}
			return "", 0, nil
		},
	}
	if err := p.Notify("Title", "Message"); err != nil {
		t.Fatalf("Notify() error = %v", err)
	}
	if !called {
		t.Error("Notify() did not invoke the backend")
	}
}

func TestLinuxPrompter_Notify_NoBackend(t *testing.T) {
	p := &LinuxPrompter{lookPath: fakeLookPath("")}
	if err := p.Notify("Title", "Message"); !errors.Is(err, errNoDialogBackend) {
		t.Errorf("Notify() error = %v, want errNoDialogBackend", err)
	}
}

func TestLinuxPrompter_RunCommandError_Propagates(t *testing.T) {
	wantErr := errors.New("exec failed")
	p := &LinuxPrompter{
		lookPath:   fakeLookPath("zenity"),
		runCommand: func(string, ...string) (string, int, error) { return "", 0, wantErr },
	}
	if _, err := p.Confirm("T", "M"); !errors.Is(err, wantErr) {
		t.Errorf("Confirm() error = %v, want %v", err, wantErr)
	}
}
