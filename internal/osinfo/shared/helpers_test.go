package shared_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

func TestReadFileContent_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	want := "hello world"
	if err := os.WriteFile(path, []byte(want), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := shared.ReadFileContent(path)
	if err != nil {
		t.Fatalf("ReadFileContent() error: %v", err)
	}
	if got != want {
		t.Errorf("ReadFileContent() = %q, want %q", got, want)
	}
}

func TestReadFileContent_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := shared.ReadFileContent(path)
	if err != nil {
		t.Fatalf("ReadFileContent() on empty file error: %v", err)
	}
	if got != "" {
		t.Errorf("ReadFileContent(empty) = %q, want %q", got, "")
	}
}

func TestReadFileContent_NotFound(t *testing.T) {
	got, err := shared.ReadFileContent(filepath.Join(t.TempDir(), "nonexistent.txt"))
	if err == nil {
		t.Error("ReadFileContent() on missing file should return error, got nil")
	}
	if got != "" {
		t.Errorf("ReadFileContent() on missing file = %q, want empty string", got)
	}
}

func TestReadFileBytes_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	want := []byte{0x01, 0x02, 0x03, 0xFF}
	if err := os.WriteFile(path, want, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := shared.ReadFileBytes(path)
	if err != nil {
		t.Fatalf("ReadFileBytes() error: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("ReadFileBytes() = %v, want %v", got, want)
	}
}

func TestReadFileBytes_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.bin")
	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := shared.ReadFileBytes(path)
	if err != nil {
		t.Fatalf("ReadFileBytes() on empty file error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("ReadFileBytes(empty) = %v, want empty", got)
	}
}

func TestReadFileBytes_NotFound(t *testing.T) {
	got, err := shared.ReadFileBytes(filepath.Join(t.TempDir(), "nonexistent.bin"))
	if err == nil {
		t.Error("ReadFileBytes() on missing file should return error, got nil")
	}
	if got != nil {
		t.Errorf("ReadFileBytes() on missing file = %v, want nil", got)
	}
}

// ── RunCommand / RunCommandOutput / RunPowerShell ───────────────────────────
//
// "go" is used as the test subprocess because it's guaranteed present on
// every CI runner (they need it to run `go test` itself), giving these
// tests real, deterministic subprocess behavior without hardcoding an
// OS-specific binary.

func TestRunCommand_Success(t *testing.T) {
	out, err := shared.RunCommand("go", "version")
	if err != nil {
		t.Fatalf("RunCommand: %v", err)
	}
	if !strings.Contains(out, "go version") {
		t.Errorf("output = %q, want it to contain %q", out, "go version")
	}
}

func TestRunCommand_CommandNotFound(t *testing.T) {
	if _, err := shared.RunCommand("sentinelgo-definitely-not-a-real-command-xyz"); err == nil {
		t.Error("expected an error for a nonexistent command")
	}
}

func TestRunCommandOutput_Success(t *testing.T) {
	out, exitCode, err := shared.RunCommandOutput("go", "version")
	if err != nil {
		t.Fatalf("RunCommandOutput: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}
	if !strings.Contains(out, "go version") {
		t.Errorf("output = %q, want it to contain %q", out, "go version")
	}
}

func TestRunCommandOutput_NonZeroExit(t *testing.T) {
	// A nonexistent package path makes `go build` fail with a real, non-zero
	// exit rather than failing to start the process at all.
	_, exitCode, err := shared.RunCommandOutput("go", "build", "./__this_package_does_not_exist_xyz__")
	if err != nil {
		t.Fatalf("RunCommandOutput should not error on a non-zero exit, got: %v", err)
	}
	if exitCode == 0 {
		t.Error("expected a non-zero exit code for a nonexistent package path")
	}
}

func TestRunCommandOutput_CommandNotFound(t *testing.T) {
	_, exitCode, err := shared.RunCommandOutput("sentinelgo-definitely-not-a-real-command-xyz")
	if err == nil {
		t.Error("expected an error for a nonexistent command")
	}
	if exitCode != -1 {
		t.Errorf("exitCode = %d, want -1 for a command that couldn't start", exitCode)
	}
}

func TestRunPowerShell_Success(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell is Windows-only")
	}
	out, err := shared.RunPowerShell("Write-Output 'hello-from-test'")
	if err != nil {
		t.Fatalf("RunPowerShell: %v", err)
	}
	if !strings.Contains(out, "hello-from-test") {
		t.Errorf("output = %q, want it to contain %q", out, "hello-from-test")
	}
}

func TestRunPowerShell_ScriptError(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell is Windows-only")
	}
	if _, err := shared.RunPowerShell("exit 1"); err == nil {
		t.Error("expected an error when the PowerShell script exits non-zero")
	}
}
