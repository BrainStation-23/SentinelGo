//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildLaunchAgentPlist(t *testing.T) {
	got := buildLaunchAgentPlist("/opt/sentinelgo/sentinelgo-epm")
	want := []string{
		`<?xml version="1.0" encoding="UTF-8"?>`,
		`<string>com.sentinelgo.epm.session</string>`,
		`<string>/opt/sentinelgo/sentinelgo-epm</string>`,
		`<string>-session</string>`,
		`<true/>`,
	}
	for _, line := range want {
		if !strings.Contains(got, line) {
			t.Errorf("buildLaunchAgentPlist() missing %q; got:\n%s", line, got)
		}
	}
}

func TestBuildLaunchAgentPlist_EscapesXML(t *testing.T) {
	got := buildLaunchAgentPlist(`/opt/a & b/sentinelgo-epm`)
	if strings.Contains(got, "a & b") {
		t.Error("buildLaunchAgentPlist() did not escape a bare & in the executable path")
	}
	if !strings.Contains(got, "a &amp; b") {
		t.Errorf("buildLaunchAgentPlist() = %s, want an escaped &amp;", got)
	}
}

func TestXmlEscape(t *testing.T) {
	cases := map[string]string{
		"plain":    "plain",
		"a & b":    "a &amp; b",
		"<tag>":    "&lt;tag&gt;",
		`"quoted"`: "&#34;quoted&#34;",
	}
	for in, want := range cases {
		if got := xmlEscape(in); got != want {
			t.Errorf("xmlEscape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDarwinAutostart_InstallThenUninstall(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	a := darwinAutostart{}
	if err := a.Install("/opt/sentinelgo/sentinelgo-epm"); err != nil {
		t.Fatalf("Install: %v", err)
	}
	dir, _ := launchAgentsDir()
	path := launchAgentPath(dir)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("plist not created: %v", err)
	}

	if err := a.Uninstall(); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("plist still exists after Uninstall: err=%v", err)
	}
}

func TestDarwinAutostart_UninstallWithoutInstallIsHarmless(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := (darwinAutostart{}).Uninstall(); err != nil {
		t.Errorf("Uninstall with nothing installed: %v", err)
	}
}

func TestLaunchAgentPath(t *testing.T) {
	got := launchAgentPath("/home/x/Library/LaunchAgents")
	want := filepath.Join("/home/x/Library/LaunchAgents", "com.sentinelgo.epm.session.plist")
	if got != want {
		t.Errorf("launchAgentPath() = %q, want %q", got, want)
	}
}
