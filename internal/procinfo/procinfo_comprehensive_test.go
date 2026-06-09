package procinfo_test

import (
	"testing"

	"sentinelgo/internal/procinfo"
)

func TestExtractVersionFromCmd_Empty(t *testing.T) {
	result := procinfo.ExtractVersionFromCmd("")
	if result != "unknown" {
		t.Errorf("ExtractVersionFromCmd(\"\") should return \"unknown\", got %s", result)
	}
}

func TestExtractVersionFromCmd_NoVersionFlag(t *testing.T) {
	result := procinfo.ExtractVersionFromCmd("/usr/bin/sentinelgo -run")
	if result != "unknown" {
		t.Errorf("ExtractVersionFromCmd() with no version flag should return \"unknown\", got %s", result)
	}
}

func TestExtractVersionFromCmd_VersionWithoutValue(t *testing.T) {
	result := procinfo.ExtractVersionFromCmd("/usr/bin/sentinelgo -version")
	if result != "unknown" {
		t.Errorf("ExtractVersionFromCmd() with version flag without value should return \"unknown\", got %s", result)
	}
}

func TestParseProcessOutput_SingleLine(t *testing.T) {
	output := `USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.0 169352 13196 ?        Ss   May12   0:04 /sbin/init`

	result := procinfo.ParseProcessOutput(output)
	if len(result) != 0 {
		t.Errorf("ParseProcessOutput() should return 0 processes for non-sentinelgo output, got %d", len(result))
	}
}

func TestParseProcessOutput_InvalidFormat(t *testing.T) {
	output := `invalid format without proper columns`

	result := procinfo.ParseProcessOutput(output)
	if len(result) != 0 {
		t.Errorf("ParseProcessOutput() should return 0 processes for invalid format, got %d", len(result))
	}
}

func TestProcessInfoStruct_DefaultValues(t *testing.T) {
	info := procinfo.ProcessInfo{}

	if info.PID != 0 {
		t.Errorf("PID should be 0 by default, got %d", info.PID)
	}
	if info.Version != "" {
		t.Errorf("Version should be empty by default, got %s", info.Version)
	}
	if info.CmdLine != "" {
		t.Errorf("CmdLine should be empty by default, got %s", info.CmdLine)
	}
	if info.Status != "" {
		t.Errorf("Status should be empty by default, got %s", info.Status)
	}
}
