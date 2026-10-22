//go:build !windows

package task

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// stubInterpreters makes lookupBinary find only the named interpreters, at
// /stub/<name>.
func stubInterpreters(t *testing.T, installed ...string) {
	t.Helper()
	orig := lookupBinary
	t.Cleanup(func() { lookupBinary = orig })
	lookupBinary = func(name string) (string, bool) {
		if slices.Contains(installed, name) {
			return "/stub/" + name, true
		}
		return "", false
	}
}

func TestScriptArgv(t *testing.T) {
	const payload = "/tmp/x/payload.json"
	tests := []struct {
		script      string
		interpreter string // base name of argv[0]; "" = the script itself
		flags       []string
	}{
		{script: "/tmp/x/run.sh", interpreter: "bash"},
		{script: "/tmp/x/run.bash", interpreter: "bash"},
		{script: "/tmp/x/run.zsh", interpreter: "zsh"},
		{script: "/tmp/x/run.py", interpreter: "python3"},
		{script: "/tmp/x/run.ps1", interpreter: "pwsh", flags: []string{"-NoProfile", "-NonInteractive", "-File"}},
		{script: "/tmp/x/run"},
		{script: "/tmp/x/run.rb"},
	}
	stubInterpreters(t, "pwsh")

	for _, tt := range tests {
		t.Run(filepath.Base(tt.script), func(t *testing.T) {
			argv, err := scriptArgv(tt.script, payload)
			if err != nil {
				t.Fatalf("scriptArgv: %v", err)
			}
			var want []string
			switch tt.interpreter {
			case "":
				want = []string{tt.script, payload}
			case "pwsh":
				want = append(append([]string{"/stub/pwsh"}, tt.flags...), tt.script, "-PayloadPath", payload)
			default:
				if filepath.Base(argv[0]) != tt.interpreter {
					t.Fatalf("argv = %q, want %s first", argv, tt.interpreter)
				}
				want = []string{argv[0], tt.script, payload}
			}
			if !slices.Equal(argv, want) {
				t.Errorf("argv = %q, want %q", argv, want)
			}
		})
	}
}

func TestScriptArgv_PwshMissing(t *testing.T) {
	stubInterpreters(t)
	argv, err := scriptArgv("/tmp/x/run.ps1", "/tmp/x/payload.json")
	if !errors.Is(err, errPwshMissing) {
		t.Fatalf("argv, err = %q, %v; want errPwshMissing", argv, err)
	}
	if !strings.Contains(err.Error(), "not installed") {
		t.Errorf("error %q should say pwsh is not installed", err)
	}
}

// TestExecuteLocalScript_ShebangNotOnLine1 runs a .bash script whose
// shebang is pushed off line 1 by a preamble, as the console's export lines
// do (sentinel-ops#308). Run directly it would fail; through bash it works.
func TestExecuteLocalScript_ShebangNotOnLine1(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "run.bash")
	body := "export LV_NAME=world\n#!/bin/bash\necho \"hello $LV_NAME ${BASH_VERSION:+bash}\"\n"
	if err := os.WriteFile(script, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	s := &TaskExecutorService{}
	out, err := s.executeLocalScript(context.Background(), script, filepath.Join(dir, "payload.json"), nil)
	if err != nil {
		t.Fatalf("executeLocalScript: %v (output %q)", err, out)
	}
	if !strings.Contains(out, "hello world bash") {
		t.Errorf("output = %q, want it run by bash", out)
	}
}

// TestExecuteLocalScript_PwshMissing: the task fails with the "not installed"
// error instead of an exec-format error.
func TestExecuteLocalScript_PwshMissing(t *testing.T) {
	stubInterpreters(t)
	dir := t.TempDir()
	script := filepath.Join(dir, "run.ps1")
	if err := os.WriteFile(script, []byte("Write-Output hi\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s := &TaskExecutorService{}
	if _, err := s.executeLocalScript(context.Background(), script, filepath.Join(dir, "payload.json"), nil); !errors.Is(err, errPwshMissing) {
		t.Errorf("err = %v, want errPwshMissing", err)
	}
}

// TestExecuteLocalScript_RealPwsh runs a .ps1 under the real pwsh when the
// host has one (GitHub's Ubuntu and macOS runners do) and checks it receives
// -PayloadPath and the task environment, as on Windows.
func TestExecuteLocalScript_RealPwsh(t *testing.T) {
	if _, ok := lookupBinary("pwsh"); !ok {
		t.Skip("pwsh not installed")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "run.ps1")
	body := "param([string]$PayloadPath)\nWrite-Output \"payload=$PayloadPath dir=$env:SENTINEL_TASK_DIR\"\nexit 3\n"
	if err := os.WriteFile(script, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(dir, "payload.json")
	s := &TaskExecutorService{}
	out, err := s.executeLocalScript(context.Background(), script, payload, []string{"SENTINEL_TASK_DIR=" + dir})
	if code, ok := exitCode(err); !ok || code != 3 {
		t.Fatalf("exit = %d, %v (err %v); want 3 (output %q)", code, ok, err, out)
	}
	if want := "payload=" + payload + " dir=" + dir; !strings.Contains(out, want) {
		t.Errorf("output = %q, want %q", out, want)
	}
}
