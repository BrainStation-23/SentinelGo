//go:build linux

package main

import (
	"os"
	"path/filepath"

	"sentinelgo/internal/epm/prompt"
)

func init() {
	newPlatformPrompter = func() prompt.Prompter { return prompt.NewLinuxPrompter() }
	newPlatformAutostart = func() autostart { return linuxAutostart{} }
}

// linuxAutostart writes an XDG autostart .desktop file — the standard
// per-user autostart mechanism honored by every major Linux desktop
// environment (GNOME, KDE, XFCE, Cinnamon, ...).
type linuxAutostart struct{}

const autostartDesktopFileName = "sentinelgo-epm.desktop"

func (linuxAutostart) Install(exePath string) error {
	dir, err := xdgAutostartDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// #nosec G306 - a .desktop autostart entry must be world-readable like
	// every other file in ~/.config/autostart; it contains no secrets.
	return os.WriteFile(filepath.Join(dir, autostartDesktopFileName), []byte(buildDesktopEntry(exePath)), 0o644)
}

func (linuxAutostart) Uninstall() error {
	dir, err := xdgAutostartDir()
	if err != nil {
		return err
	}
	err = os.Remove(filepath.Join(dir, autostartDesktopFileName))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// xdgAutostartDir resolves ~/.config/autostart, honoring $XDG_CONFIG_HOME
// per the XDG Base Directory Specification.
func xdgAutostartDir() (string, error) {
	if base := os.Getenv("XDG_CONFIG_HOME"); base != "" {
		return filepath.Join(base, "autostart"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "autostart"), nil
}

// buildDesktopEntry is split out from Install for testability without
// touching the real filesystem. exePath is quoted in Exec= the same way
// buildRunCommand quotes it on Windows — a path is not guaranteed to be
// space-free, and .desktop Exec parsing follows shell-like quoting rules.
func buildDesktopEntry(exePath string) string {
	return "[Desktop Entry]\n" +
		"Type=Application\n" +
		"Name=SentinelGo EPM Session Helper\n" +
		`Exec="` + exePath + `" -session` + "\n" +
		"X-GNOME-Autostart-enabled=true\n" +
		"NoDisplay=true\n"
}
