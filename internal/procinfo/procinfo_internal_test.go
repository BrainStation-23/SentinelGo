package procinfo

import "testing"

// White-box tests for the unexported helpers extracted from ParseProcessOutput
// and GetBinaryVersion during the cognitive-complexity refactor.

func TestExtractVersionFromOutput_Found(t *testing.T) {
	got := extractVersionFromOutput("sentinelgo version: v1.2.3\n")
	if got != "v1.2.3" {
		t.Errorf("extractVersionFromOutput() = %q, want %q", got, "v1.2.3")
	}
}

func TestExtractVersionFromOutput_TrimsTrailingComma(t *testing.T) {
	got := extractVersionFromOutput("build info: version v1.2.3, commit abc123\n")
	if got != "v1.2.3" {
		t.Errorf("extractVersionFromOutput() = %q, want %q", got, "v1.2.3")
	}
}

func TestExtractVersionFromOutput_NoVersionLine(t *testing.T) {
	got := extractVersionFromOutput("some unrelated output\nwith no matching line\n")
	if got != "" {
		t.Errorf("extractVersionFromOutput() = %q, want empty string", got)
	}
}

func TestExtractVersionFromOutput_VersionWordButNoFollowingToken(t *testing.T) {
	got := extractVersionFromOutput("version")
	if got != "" {
		t.Errorf("extractVersionFromOutput() = %q, want empty string when version is the last token", got)
	}
}

func TestExtractVersionFromOutput_Empty(t *testing.T) {
	if got := extractVersionFromOutput(""); got != "" {
		t.Errorf("extractVersionFromOutput(\"\") = %q, want empty string", got)
	}
}

func TestResolveBinaryPath_Empty(t *testing.T) {
	if got := resolveBinaryPath(""); got != "" {
		t.Errorf("resolveBinaryPath(\"\") = %q, want empty string", got)
	}
}

func TestResolveBinaryPath_AbsolutePathUnchanged(t *testing.T) {
	got := resolveBinaryPath("/opt/sentinelgo/sentinelgo -run --config /etc/config.json")
	if got != "/opt/sentinelgo/sentinelgo" {
		t.Errorf("resolveBinaryPath() = %q, want %q", got, "/opt/sentinelgo/sentinelgo")
	}
}

func TestParseUnixProcessLine_ValidEntry(t *testing.T) {
	// ps aux columns: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND...
	line := "root      1234  0.1  0.2 123456  7890 ?        Ssl  10:00   0:05 /opt/sentinelgo/sentinelgo -run --config /etc/sentinelgo/config.json"
	info := parseUnixProcessLine(line)
	if info.PID != 1234 {
		t.Errorf("PID = %d, want 1234", info.PID)
	}
	if info.Status != "Running" {
		t.Errorf("Status = %q, want %q", info.Status, "Running")
	}
	if info.CmdLine == "" {
		t.Error("CmdLine should not be empty")
	}
}

func TestParseUnixProcessLine_NotSentinelGo(t *testing.T) {
	info := parseUnixProcessLine("root 1 0.0 0.0 1000 100 ? Ss 10:00 0:01 /sbin/init")
	if info.PID != 0 {
		t.Errorf("PID = %d, want 0 for a non-sentinelgo line", info.PID)
	}
}

func TestParseUnixProcessLine_ExcludedTools(t *testing.T) {
	for _, excl := range []string{"grep", "systemctl", "journalctl", "editor"} {
		line := "root 999 0.0 0.0 1000 100 ? Ss 10:00 0:01 " + excl + " sentinelgo"
		info := parseUnixProcessLine(line)
		if info.PID != 0 {
			t.Errorf("parseUnixProcessLine with %q should be excluded, got PID=%d", excl, info.PID)
		}
	}
}

func TestParseUnixProcessLine_TooFewFields(t *testing.T) {
	info := parseUnixProcessLine("root 1234 sentinelgo")
	if info.PID != 0 {
		t.Errorf("PID = %d, want 0 for a line with too few fields", info.PID)
	}
}
