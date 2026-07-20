package main

import (
	"flag"
	"os"
	"testing"
)

// resetFlags resets the global flag.CommandLine so parseFlags() can be called
// multiple times within a test suite without "flag redefined" panics.
func resetFlags(args []string) {
	os.Args = append([]string{"sentinelgo"}, args...)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
}

func TestParseFlags_defaults(t *testing.T) {
	resetFlags(nil)
	f := parseFlags()

	if f == nil {
		t.Fatal("parseFlags() returned nil")
		return // Early return to satisfy staticcheck
	}
	if f.install == nil {
		t.Fatal("install flag is nil")
	}
	if f.uninstall == nil {
		t.Fatal("uninstall flag is nil")
	}
	if f.version == nil {
		t.Fatal("version flag is nil")
	}
	if f.cfgPath == nil {
		t.Fatal("cfgPath flag is nil")
	}
	if *f.install {
		t.Error("install should default to false")
	}
	if *f.uninstall {
		t.Error("uninstall should default to false")
	}
	if *f.version {
		t.Error("version should default to false")
	}
	if *f.cfgPath != "" {
		t.Errorf("cfgPath should default to empty, got %q", *f.cfgPath)
	}
}

func TestParseFlags_version(t *testing.T) {
	resetFlags([]string{"-version"})
	f := parseFlags()

	if !*f.version {
		t.Error("expected -version flag to be true")
	}
}

func TestParseFlags_install(t *testing.T) {
	resetFlags([]string{"-install"})
	f := parseFlags()

	if !*f.install {
		t.Error("expected -install flag to be true")
	}
}

func TestParseFlags_configPath(t *testing.T) {
	resetFlags([]string{"-config", "/etc/sentinelgo/config.json"})
	f := parseFlags()

	if *f.cfgPath != "/etc/sentinelgo/config.json" {
		t.Errorf("cfgPath = %q, want /etc/sentinelgo/config.json", *f.cfgPath)
	}
}

func TestParseFlags_softwareList(t *testing.T) {
	resetFlags([]string{"-software-list"})
	f := parseFlags()

	if !*f.softwareList {
		t.Error("expected -software-list to be true")
	}
}

func TestParseFlags_agentTaskManager(t *testing.T) {
	resetFlags([]string{"-agent-task-manager"})
	f := parseFlags()

	if !*f.agentTaskManager {
		t.Error("expected -agent-task-manager to be true")
	}
}
