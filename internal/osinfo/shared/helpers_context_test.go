package shared

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

// sleepCommand returns a command that sleeps for roughly d seconds on the
// current platform, used to prove cancellation actually stops the child.
func sleepCommand(seconds int) (string, []string) {
	if runtime.GOOS == "windows" {
		// ping -n <n+1> to localhost is the classic dependency-free Windows sleep.
		return "cmd", []string{"/c", "ping", "-n", itoa(seconds + 1), "127.0.0.1"}
	}
	return "sleep", []string{itoa(seconds)}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestRunCommandContextCancels is the reason this helper exists: a subprocess
// must not outlive the cycle that started it.
//
// The existing RunCommand uses its own 30-second internal timeout and ignores
// the caller's deadline entirely, so a telemetry cycle that times out at 15s
// would leave the command running. This asserts the context variant returns
// promptly when cancelled.
func TestRunCommandContextCancels(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a subprocess")
	}

	name, args := sleepCommand(30)
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not available: %v", name, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := RunCommandContext(ctx, name, args...)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error when the context expires")
	}
	// Generous bound: the point is that it returns in well under the 30s the
	// command would otherwise take, and under RunCommand's 30s internal timeout.
	if elapsed > 10*time.Second {
		t.Fatalf("cancellation took %v; the subprocess was not terminated promptly", elapsed)
	}
}

// TestRunCommandContextAlreadyCancelled checks the degenerate case.
func TestRunCommandContextAlreadyCancelled(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a subprocess")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	name, args := sleepCommand(5)
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not available: %v", name, err)
	}

	if _, err := RunCommandContext(ctx, name, args...); err == nil {
		t.Fatal("expected an error for an already-cancelled context")
	}
}

// TestRunCommandContextSuccess verifies the normal path still returns stdout.
func TestRunCommandContextSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a subprocess")
	}

	var name string
	var args []string
	if runtime.GOOS == "windows" {
		name, args = "cmd", []string{"/c", "echo", "hello"}
	} else {
		name, args = "echo", []string{"hello"}
	}
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not available: %v", name, err)
	}

	out, err := RunCommandContext(context.Background(), name, args...)
	if err != nil {
		t.Fatalf("RunCommandContext: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected output from echo")
	}
}

// TestRunCommandOutputContextKeepsNonZeroExit is the smartctl case: a non-zero
// exit code must still yield its output, because tools like smartctl encode
// drive health in exit-code bit flags. Discarding stdout there would lose data
// for exactly the failing drives that matter.
func TestRunCommandOutputContextKeepsNonZeroExit(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a subprocess")
	}

	var name string
	var args []string
	if runtime.GOOS == "windows" {
		name, args = "cmd", []string{"/c", "echo marker && exit 3"}
	} else {
		name, args = "sh", []string{"-c", "echo marker; exit 3"}
	}
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not available: %v", name, err)
	}

	out, code, err := RunCommandOutputContext(context.Background(), name, args...)
	if err != nil {
		t.Fatalf("execution error should be nil for a non-zero exit: %v", err)
	}
	if code != 3 {
		t.Errorf("exit code = %d, want 3", code)
	}
	if len(out) == 0 {
		t.Error("output must be preserved despite the non-zero exit")
	}
}

// TestRunCommandOutputContextMissingBinary checks the classification path the
// telemetry error sanitizer depends on.
func TestRunCommandOutputContextMissingBinary(t *testing.T) {
	_, code, err := RunCommandOutputContext(context.Background(), "sentinelgo-no-such-binary-xyz")
	if err == nil {
		t.Fatal("expected an error for a missing binary")
	}
	if code != -1 {
		t.Errorf("exit code = %d, want -1 for a failed launch", code)
	}
	if !errors.Is(err, exec.ErrNotFound) && !errors.As(err, new(*exec.Error)) {
		t.Errorf("error should be recognisable as a lookup failure, got %T: %v", err, err)
	}
}
