package sanitize_test

import (
	"encoding/json"
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

func TestStripNUL_PlainString_Unchanged(t *testing.T) {
	input := "Mozilla Firefox 120.0"
	got := sanitize.StripNUL(input)
	if got != input {
		t.Errorf("StripNUL(%q) = %q, want unchanged", input, got)
	}
}

func TestStripNUL_Empty_ReturnsEmpty(t *testing.T) {
	if got := sanitize.StripNUL(""); got != "" {
		t.Errorf("StripNUL(\"\") = %q, want empty string", got)
	}
}

func TestStripNUL_StripsEmbeddedNUL(t *testing.T) {
	input := "a\x00b"
	got := sanitize.StripNUL(input)
	if strings.ContainsRune(got, 0) {
		t.Errorf("StripNUL should remove NUL bytes; got %q", got)
	}
	if got != "ab" {
		t.Errorf("StripNUL(%q) = %q, want %q", input, got, "ab")
	}
}

func TestStripNUL_MultipleNULs(t *testing.T) {
	input := "\x00a\x00\x00b\x00"
	got := sanitize.StripNUL(input)
	if got != "ab" {
		t.Errorf("StripNUL(%q) = %q, want %q", input, got, "ab")
	}
}

func TestStripNUL_OnlyNULs_ReturnsEmpty(t *testing.T) {
	if got := sanitize.StripNUL("\x00\x00\x00"); got != "" {
		t.Errorf("StripNUL of only NULs = %q, want empty string", got)
	}
}

// stripJSONNULValue marshals v, runs it through StripJSONNUL, fails the test if
// the result is not valid JSON or if any decoded string still contains a real NUL
// byte, and returns the cleaned bytes. It decodes and walks the result rather than
// substring-matching the escape, because a value that legitimately contains the
// literal text of the escape is rendered with a doubled backslash and must pass.
func stripJSONNULValue(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := sanitize.StripJSONNUL(raw)
	if !json.Valid(got) {
		t.Fatalf("StripJSONNUL produced invalid JSON: %q", got)
	}
	var decoded any
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("unmarshal cleaned JSON: %v", err)
	}
	if jsonHasNUL(decoded) {
		t.Fatalf("StripJSONNUL left a real NUL in a decoded value: %q", got)
	}
	return got
}

// jsonHasNUL reports whether any string within a decoded JSON value contains a
// real NUL byte (U+0000).
func jsonHasNUL(v any) bool {
	switch x := v.(type) {
	case string:
		return strings.ContainsRune(x, 0)
	case []any:
		for _, e := range x {
			if jsonHasNUL(e) {
				return true
			}
		}
	case map[string]any:
		for _, e := range x {
			if jsonHasNUL(e) {
				return true
			}
		}
	}
	return false
}

func TestStripJSONNUL_RemovesEncodedNUL(t *testing.T) {
	got := stripJSONNULValue(t, map[string]string{"name": "a\x00b"})

	var out map[string]string
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out["name"] != "ab" {
		t.Errorf("value after strip = %q, want %q", out["name"], "ab")
	}
}

func TestStripJSONNUL_PreservesLiteralEscapeText(t *testing.T) {
	// A value that literally contains the six characters of the NUL escape must
	// survive: the encoder writes it with a doubled leading backslash, which is not
	// an encoded NUL and must be left intact.
	literal := "\\u0000"
	got := stripJSONNULValue(t, map[string]string{"name": literal})

	var out map[string]string
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out["name"] != literal {
		t.Errorf("literal text was corrupted: got %q, want %q", out["name"], literal)
	}
}

func TestStripJSONNUL_BackslashBeforeNUL(t *testing.T) {
	// A backslash immediately followed by a real NUL marshals to three backslashes
	// then u0000 (two for the escaped backslash, one starting the NUL escape).
	// Stripping the NUL must leave a single backslash, not corrupt the escaping.
	got := stripJSONNULValue(t, map[string]string{"name": "\\\x00"})

	var out map[string]string
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out["name"] != "\\" {
		t.Errorf("value after strip = %q, want %q", out["name"], "\\")
	}
}

func TestStripJSONNUL_NoNUL_Unchanged(t *testing.T) {
	raw, err := json.Marshal(map[string]string{"name": "clean value"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := sanitize.StripJSONNUL(raw)
	if string(got) != string(raw) {
		t.Errorf("StripJSONNUL changed NUL-free JSON: got %q, want %q", got, raw)
	}
}
