//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildDesktopEntry(t *testing.T) {
	got := buildDesktopEntry("/opt/sentinelgo/sentinelgo-epm")
	want := []string{
		"[Desktop Entry]",
		"Type=Application",
		`Exec="/opt/sentinelgo/sentinelgo-epm" -session`,
		"X-GNOME-Autostart-enabled=true",
	}
	for _, line := range want {
		if !strings.Contains(got, line) {
			t.Errorf("buildDesktopEntry() missing line %q; got:\n%s", line, got)
		}
	}
}

func TestXdgAutostartDir_HonorsXDGConfigHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/custom/config")
	dir, err := xdgAutostartDir()
	if err != nil {
		t.Fatalf("xdgAutostartDir: %v", err)
	}
	if dir != "/custom/config/autostart" {
		t.Errorf("xdgAutostartDir() = %q, want /custom/config/autostart", dir)
	}
}

func TestXdgAutostartDir_FallsBackToHomeConfig(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	dir, err := xdgAutostartDir()
	if err != nil {
		t.Fatalf("xdgAutostartDir: %v", err)
	}
	if !strings.HasSuffix(dir, filepath.Join(".config", "autostart")) {
		t.Errorf("xdgAutostartDir() = %q, want a path ending in .config/autostart", dir)
	}
}

func TestLinuxAutostart_InstallThenUninstall(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	a := linuxAutostart{}

	if err := a.Install("/opt/sentinelgo/sentinelgo-epm"); err != nil {
		t.Fatalf("Install: %v", err)
	}
	dir, _ := xdgAutostartDir()
	path := filepath.Join(dir, autostartDesktopFileName)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("desktop file not created: %v", err)
	}

	if err := a.Uninstall(); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("desktop file still exists after Uninstall: err=%v", err)
	}
}

func TestLinuxAutostart_UninstallWithoutInstallIsHarmless(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := (linuxAutostart{}).Uninstall(); err != nil {
		t.Errorf("Uninstall with nothing installed: %v", err)
	}
}
