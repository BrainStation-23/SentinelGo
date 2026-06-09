//go:build windows

package collector

// Pure-logic tests for the Windows collector. They run on the Windows host. The
// event-reading path (EvtQuery/EvtRender) needs real OS handles and is covered
// by integration runs, not here.

import "testing"

func TestGenerateSource(t *testing.T) {
	cases := map[string]string{
		"Security": "windows_security",
		"Microsoft-Windows-PowerShell/Operational": "windows_microsoft_windows_powershell_operational",
		"Windows Defender/Operational":             "windows_windows_defender_operational",
	}
	for in, want := range cases {
		if got := generateSource(in); got != want {
			t.Errorf("generateSource(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWindowsLevelToSeverity(t *testing.T) {
	cases := map[int]string{
		1: "2", // Critical
		2: "3", // Error
		3: "4", // Warning
		4: "6", // Information
		5: "7", // Verbose
		9: "6", // unknown -> info
	}
	for level, want := range cases {
		if got := windowsLevelToSeverity(level); got != want {
			t.Errorf("windowsLevelToSeverity(%d) = %q, want %q", level, got, want)
		}
	}
}
