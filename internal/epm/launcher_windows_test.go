//go:build windows

package epm

import "testing"

func TestBuildCommandLine_NoExtraArgs(t *testing.T) {
	got := buildCommandLine(`C:\apps\tool.exe`, "")
	want := `"C:\apps\tool.exe"`
	if got != want {
		t.Errorf("buildCommandLine = %q, want %q", got, want)
	}
}

func TestBuildCommandLine_WithExtraArgs(t *testing.T) {
	got := buildCommandLine(`C:\apps\tool.exe`, "--flag value")
	want := `"C:\apps\tool.exe" --flag value`
	if got != want {
		t.Errorf("buildCommandLine = %q, want %q", got, want)
	}
}

func TestQuoteWindowsArg_OrdinaryBackslashesUntouched(t *testing.T) {
	got := quoteWindowsArg(`C:\Program Files\App\tool.exe`)
	want := `"C:\Program Files\App\tool.exe"`
	if got != want {
		t.Errorf("quoteWindowsArg = %q, want %q", got, want)
	}
}

func TestQuoteWindowsArg_TrailingBackslashDoubledBeforeClosingQuote(t *testing.T) {
	got := quoteWindowsArg(`C:\apps\`)
	want := `"C:\apps\\"`
	if got != want {
		t.Errorf("quoteWindowsArg = %q, want %q", got, want)
	}
}

func TestQuoteWindowsArg_EmbeddedQuoteIsEscaped(t *testing.T) {
	got := quoteWindowsArg(`say "hi"`)
	want := `"say \"hi\""`
	if got != want {
		t.Errorf("quoteWindowsArg = %q, want %q", got, want)
	}
}
