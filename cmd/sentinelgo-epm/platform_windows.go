//go:build windows

package main

import (
	"sentinelgo/internal/epm/prompt"

	"golang.org/x/sys/windows/registry"
)

func init() {
	newPlatformPrompter = func() prompt.Prompter { return prompt.NewWindowsPrompter() }
	newPlatformAutostart = func() autostart { return windowsAutostart{} }
}

// windowsAutostart registers "sentinelgo-epm -session" under the current
// user's Run key (HKCU\Software\Microsoft\Windows\CurrentVersion\Run) — the
// standard, simplest per-user autostart mechanism on Windows, run once at
// each interactive logon. A per-user Scheduled Task is the plan's other
// suggested option; the Run key is preferred here for being a single
// registry value write with no separate task-definition XML to build.
type windowsAutostart struct{}

const (
	runKeyPath  = `Software\Microsoft\Windows\CurrentVersion\Run`
	runValueKey = "SentinelGoEPM"
)

func (windowsAutostart) Install(exePath string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(runValueKey, buildRunCommand(exePath))
}

func (windowsAutostart) Uninstall() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			return nil
		}
		return err
	}
	defer k.Close()
	err = k.DeleteValue(runValueKey)
	if err == registry.ErrNotExist {
		return nil
	}
	return err
}

// buildRunCommand quotes exePath (Run-key values are parsed as a shell
// command line, so a path containing spaces — e.g. "C:\Program Files\...\"
// — must be quoted or Windows splits it at the first space) and appends
// -session. Split out from Install for testability without a real registry.
func buildRunCommand(exePath string) string {
	return `"` + exePath + `" -session`
}
