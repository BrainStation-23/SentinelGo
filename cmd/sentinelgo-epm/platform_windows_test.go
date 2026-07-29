//go:build windows

package main

import "testing"

func TestBuildRunCommand(t *testing.T) {
	cases := map[string]string{
		`C:\SentinelGo\sentinelgo-epm.exe`:    `"C:\SentinelGo\sentinelgo-epm.exe" -session`,
		`C:\Program Files\SentinelGo\epm.exe`: `"C:\Program Files\SentinelGo\epm.exe" -session`,
	}
	for in, want := range cases {
		if got := buildRunCommand(in); got != want {
			t.Errorf("buildRunCommand(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWindowsAutostart_InstallThenUninstall(t *testing.T) {
	a := windowsAutostart{}
	if err := a.Install(`C:\test\sentinelgo-epm.exe`); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := a.Uninstall(); err != nil {
		t.Errorf("Uninstall: %v", err)
	}
}

func TestWindowsAutostart_UninstallWithoutInstallIsHarmless(t *testing.T) {
	a := windowsAutostart{}
	if err := a.Uninstall(); err != nil {
		t.Errorf("Uninstall with nothing installed: %v", err)
	}
}
