//go:build linux

package task

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestLinuxScriptCommand_SudoKeepsEnv: sudo resets the environment, so the
// task's variables must be on the command line, through env(1), before the
// interpreter.
func TestLinuxScriptCommand_SudoKeepsEnv(t *testing.T) {
	env := []string{"SENTINEL_TASK_ID=t1", "SENTINEL_TASK_DIR=/tmp/x y"}
	cmd := mustLinuxScriptCommand(t, "/tmp/x/run.sh", "/tmp/x/payload.json", env, true)

	args := cmd.Args[1:]
	if args[0] != "-S" {
		t.Fatalf("args = %q, want sudo -S first", args)
	}
	if filepath.Base(args[1]) != "env" {
		t.Fatalf("args = %q, want env(1) after -S", args)
	}
	if !slices.Equal(args[2:4], env) {
		t.Errorf("env args = %q, want %q", args[2:4], env)
	}
	if filepath.Base(args[4]) != "bash" || args[5] != "/tmp/x/run.sh" || args[6] != "/tmp/x/payload.json" {
		t.Errorf("command = %q, want bash run.sh payload.json", args[4:])
	}
}

func TestLinuxScriptCommand_SudoNoEnv(t *testing.T) {
	cmd := mustLinuxScriptCommand(t, "/tmp/x/run.py", "/tmp/x/p.json", nil, true)
	args := cmd.Args[1:]
	if args[0] != "-S" || filepath.Base(args[1]) != "python3" {
		t.Errorf("args = %q, want -S python3 …", args)
	}
}

func TestLinuxScriptCommand_NoSudoSetsEnv(t *testing.T) {
	cmd := mustLinuxScriptCommand(t, "/tmp/x/run", "/tmp/x/p.json", []string{"SENTINEL_TASK_ID=t1"}, false)
	if cmd.Args[0] != "/tmp/x/run" {
		t.Errorf("args = %q, want the script run directly", cmd.Args)
	}
	if !slices.Contains(cmd.Env, "SENTINEL_TASK_ID=t1") {
		t.Error("env var missing from cmd.Env")
	}
}

// TestLinuxScriptCommand_EnvReachesScript runs the env(1) wrapper for real
// (without sudo, which needs a password in CI) and checks the script sees the
// variables even with a scrubbed parent environment, as under sudo.
func TestLinuxScriptCommand_EnvReachesScript(t *testing.T) {
	envBin, err := exec.LookPath("env")
	if err != nil {
		t.Skip("env(1) not available")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(script, []byte("echo \"id=$SENTINEL_TASK_ID dir=$SENTINEL_TASK_DIR\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	sudoCmd := mustLinuxScriptCommand(t, script, filepath.Join(dir, "p.json"),
		[]string{"SENTINEL_TASK_ID=t1", "SENTINEL_TASK_DIR=" + dir}, true)

	// Replace sudo with env -i (an empty environment, like env_reset) and run
	// the rest of the argument list unchanged.
	args := append([]string{"-i"}, sudoCmd.Args[2:]...)
	out, err := exec.Command(envBin, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v: %s", err, out)
	}
	if want := "id=t1 dir=" + dir; !strings.Contains(string(out), want) {
		t.Errorf("output = %q, want %q", out, want)
	}
}

// mustLinuxScriptCommand builds the command and fails the test on an error.
func mustLinuxScriptCommand(t *testing.T, scriptPath, payloadPath string, env []string, needsSudo bool) *exec.Cmd {
	t.Helper()
	cmd, err := linuxScriptCommand(context.Background(), scriptPath, payloadPath, env, needsSudo)
	if err != nil {
		t.Fatalf("linuxScriptCommand(%q): %v", scriptPath, err)
	}
	return cmd
}

// TestLinuxScriptCommand_SudoPwsh: a .ps1 under sudo keeps the env(1) wrapper
// and runs pwsh with the same arguments as Windows (#222).
func TestLinuxScriptCommand_SudoPwsh(t *testing.T) {
	stubInterpreters(t, "pwsh")
	cmd := mustLinuxScriptCommand(t, "/tmp/x/run.ps1", "/tmp/x/p.json", []string{"SENTINEL_TASK_ID=t1"}, true)
	args := cmd.Args[1:]
	want := []string{"/stub/pwsh", "-NoProfile", "-NonInteractive", "-File", "/tmp/x/run.ps1", "-PayloadPath", "/tmp/x/p.json"}
	if args[0] != "-S" || filepath.Base(args[1]) != "env" || args[2] != "SENTINEL_TASK_ID=t1" || !slices.Equal(args[3:], want) {
		t.Errorf("args = %q, want -S env SENTINEL_TASK_ID=t1 %q", args, want)
	}
}

func TestLinuxScriptCommand_PwshMissing(t *testing.T) {
	stubInterpreters(t)
	for _, sudo := range []bool{false, true} {
		if _, err := linuxScriptCommand(context.Background(), "/tmp/x/run.ps1", "/tmp/x/p.json", nil, sudo); !errors.Is(err, errPwshMissing) {
			t.Errorf("sudo=%v: err = %v, want errPwshMissing", sudo, err)
		}
	}
}
