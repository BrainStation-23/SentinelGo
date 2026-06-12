package sanitize_test

import (
	"strings"
	"testing"

	"sentinelgo/internal/sanitize"
)

func TestForLog_PlainString_Unchanged(t *testing.T) {
	input := "v1.2.3"
	got := sanitize.ForLog(input)
	if got != input {
		t.Errorf("ForLog(%q) = %q, want %q", input, got, input)
	}
}

func TestForLog_Empty_ReturnsEmpty(t *testing.T) {
	got := sanitize.ForLog("")
	if got != "" {
		t.Errorf("ForLog(\"\") = %q, want empty string", got)
	}
}

func TestForLog_StripNewline(t *testing.T) {
	input := "line1\nline2"
	got := sanitize.ForLog(input)
	if strings.Contains(got, "\n") {
		t.Errorf("ForLog should strip newlines; got: %q", got)
	}
}

func TestForLog_StripCarriageReturn(t *testing.T) {
	input := "value\r\ninjected"
	got := sanitize.ForLog(input)
	if strings.Contains(got, "\r") || strings.Contains(got, "\n") {
		t.Errorf("ForLog should strip \\r and \\n; got: %q", got)
	}
}

func TestForLog_StripCRLF(t *testing.T) {
	input := "INFO level\r\nERROR injected"
	got := sanitize.ForLog(input)
	if strings.Contains(got, "\r") || strings.Contains(got, "\n") {
		t.Errorf("ForLog should strip CRLF; got: %q", got)
	}
	if !strings.Contains(got, "INFO level") || !strings.Contains(got, "ERROR injected") {
		t.Errorf("ForLog should preserve non-whitespace content; got: %q", got)
	}
}

func TestForLog_MultipleNewlines(t *testing.T) {
	input := "a\nb\nc\n\n"
	got := sanitize.ForLog(input)
	if strings.Contains(got, "\n") {
		t.Errorf("ForLog should strip all newlines; got: %q", got)
	}
}

func TestForLog_OnlyNewlines(t *testing.T) {
	got := sanitize.ForLog("\n\r\n\r")
	if got != "" {
		t.Errorf("ForLog with only whitespace characters: got %q, want empty string", got)
	}
}

func TestForLog_PreservesOtherContent(t *testing.T) {
	input := "version=v2.0.0 arch=amd64 os=linux"
	got := sanitize.ForLog(input)
	if got != input {
		t.Errorf("ForLog should preserve content without newlines; got %q, want %q", got, input)
	}
}

func TestForLog_LogInjectionPrevention(t *testing.T) {
	// Simulate an attacker-controlled value that tries to inject a log line.
	malicious := "v1.0.0\n2025-01-01 00:00:00 ERROR: injected log entry"
	got := sanitize.ForLog(malicious)
	lines := strings.Split(got, "\n")
	if len(lines) > 1 {
		t.Errorf("ForLog should prevent log injection; got %d lines: %q", len(lines), got)
	}
}

func TestForLog_TabAndSpacePreserved(t *testing.T) {
	input := "key\tvalue  spaced"
	got := sanitize.ForLog(input)
	if got != input {
		t.Errorf("ForLog should preserve tabs and spaces; got %q, want %q", got, input)
	}
}
