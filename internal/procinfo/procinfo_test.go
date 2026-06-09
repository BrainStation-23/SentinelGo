package procinfo_test

import (
	"runtime"
	"testing"

	"sentinelgo/internal/procinfo"
)

func TestExtractVersionFromCmd(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cmdLine  string
		expected string
	}{
		{
			name:     "version flag with equals",
			cmdLine:  "/opt/sentinelgo/sentinelgo -version=v2.3.0 -run",
			expected: "v2.3.0",
		},
		{
			name:     "version flag as separate arg",
			cmdLine:  "/opt/sentinelgo/sentinelgo -version v2.3.0",
			expected: "v2.3.0",
		},
		{
			name:     "double dash version flag",
			cmdLine:  "/opt/sentinelgo/sentinelgo --version v1.0.0",
			expected: "v1.0.0",
		},
		{
			name:     "no version flag",
			cmdLine:  "/opt/sentinelgo/sentinelgo -run",
			expected: "unknown",
		},
		{
			name:     "empty command line",
			cmdLine:  "",
			expected: "unknown",
		},
		{
			name:     "version flag at end without value",
			cmdLine:  "/opt/sentinelgo/sentinelgo -version",
			expected: "unknown",
		},
		{
			name:     "quoted version value",
			cmdLine:  `/opt/sentinelgo -version="v3.0.0" -run`,
			expected: "v3.0.0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := procinfo.ExtractVersionFromCmd(tc.cmdLine)
			if result != tc.expected {
				t.Errorf("ExtractVersionFromCmd(%q) = %q, want %q", tc.cmdLine, result, tc.expected)
			}
		})
	}
}

func TestParseProcessOutput_EmptyInput(t *testing.T) {
	t.Parallel()

	result := procinfo.ParseProcessOutput("")
	if len(result) != 0 {
		t.Errorf("expected 0 processes for empty input, got %d", len(result))
	}
}

func TestParseProcessOutput_WhitespaceOnly(t *testing.T) {
	t.Parallel()

	result := procinfo.ParseProcessOutput("   \n  \n\n")
	if len(result) != 0 {
		t.Errorf("expected 0 processes for whitespace input, got %d", len(result))
	}
}

func TestParseProcessOutput_NoSentinelGoProcess(t *testing.T) {
	t.Parallel()

	output := `USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.0 169352 13196 ?        Ss   May12   0:04 /sbin/init
root       456  0.0  0.0  72308  6128 ?        Ss   May12   0:00 /usr/sbin/sshd
`
	result := procinfo.ParseProcessOutput(output)
	if len(result) != 0 {
		t.Errorf("expected 0 sentinelgo processes, got %d", len(result))
	}
}

func TestGetCheckpointPath(t *testing.T) {
	t.Parallel()

	path := procinfo.GetCheckpointPath()
	if path == "" {
		t.Error("GetCheckpointPath() returned empty string")
	}

	const expectedSuffix = "audit_checkpoint.json"
	if len(path) < len(expectedSuffix) || path[len(path)-len(expectedSuffix):] != expectedSuffix {
		t.Errorf("GetCheckpointPath() = %q, expected suffix %q", path, expectedSuffix)
	}
}

func TestProcessInfoStruct(t *testing.T) {
	t.Parallel()

	info := procinfo.ProcessInfo{
		PID:     1234,
		Version: "v2.3.0",
		CmdLine: "/opt/sentinelgo/sentinelgo -run",
		Status:  "Running",
	}

	if info.PID != 1234 {
		t.Errorf("expected PID 1234, got %d", info.PID)
	}
	if info.Version != "v2.3.0" {
		t.Errorf("expected version v2.3.0, got %s", info.Version)
	}
	if info.Status != "Running" {
		t.Errorf("expected status Running, got %s", info.Status)
	}
	if info.CmdLine == "" {
		t.Error("expected non-empty CmdLine")
	}
}

func TestProcessInfoStruct_EmptyFields(t *testing.T) {
	t.Parallel()

	// Should not panic with zero-value fields
	_ = procinfo.ProcessInfo{}
}

func TestExtractVersionFromCmd_VersionInMiddle(t *testing.T) {
	t.Parallel()

	cmdLine := "/opt/sentinelgo/sentinelgo -version=v1.2.3 -run -config=test.json"
	result := procinfo.ExtractVersionFromCmd(cmdLine)
	if result != "v1.2.3" {
		t.Errorf("ExtractVersionFromCmd() = %q, want v1.2.3", result)
	}
}

func TestExtractVersionFromCmd_MultipleVersionFlags(t *testing.T) {
	t.Parallel()

	cmdLine := "/opt/sentinelgo/sentinelgo -version=v1.0.0 -version=v2.0.0"
	result := procinfo.ExtractVersionFromCmd(cmdLine)
	// Should return the first match
	if result != "v1.0.0" {
		t.Errorf("ExtractVersionFromCmd() = %q, want v1.0.0", result)
	}
}

func TestExtractVersionFromCmd_VersionWithSpaces(t *testing.T) {
	t.Parallel()

	// Should not panic with a space after the equals sign
	procinfo.ExtractVersionFromCmd("/opt/sentinelgo/sentinelgo -version= v1.0.0")
}

func TestParseProcessOutput_SingleProcess(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("test uses Linux ps aux format, not applicable on Windows")
	}

	output := `USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root      1234  0.0  0.0 169352 13196 ?        Ss   May12   0:04 /opt/sentinelgo/sentinelgo -version=v2.3.0 -run
`
	result := procinfo.ParseProcessOutput(output)
	if len(result) != 1 {
		t.Errorf("expected 1 process, got %d", len(result))
	}
}

func TestParseProcessOutput_MultipleProcesses(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("test uses Linux ps aux format, not applicable on Windows")
	}

	output := `USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root      1234  0.0  0.0 169352 13196 ?        Ss   May12   0:04 /opt/sentinelgo/sentinelgo -version=v2.3.0 -run
root      1235  0.0  0.0 169352 13196 ?        Ss   May12   0:04 /opt/sentinelgo/sentinelgo -version=v2.3.0 -run
`
	result := procinfo.ParseProcessOutput(output)
	if len(result) != 2 {
		t.Errorf("expected 2 processes, got %d", len(result))
	}
}

func TestFindProcesses(t *testing.T) {
	t.Parallel()

	// This test just verifies the function doesn't panic
	processes, err := procinfo.FindProcesses()
	_ = processes
	_ = err
}
