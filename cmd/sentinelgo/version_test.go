package main

import (
	"strings"
	"testing"

	"sentinelgo/internal/config"
)

func TestGetVersion_ldflags(t *testing.T) {
	orig := Version
	defer func() { Version = orig }()

	Version = "v1.2.3"
	got := GetVersion()
	if got != "v1.2.3" {
		t.Errorf("GetVersion() = %q, want %q", got, "v1.2.3")
	}
}

func TestGetVersion_fallback(t *testing.T) {
	orig := Version
	defer func() { Version = orig }()

	Version = ""
	got := GetVersion()
	// Falls back to config.Version which is injected at build time or "dev".
	if got != config.Version && got != "dev" && !strings.HasPrefix(got, "v") {
		t.Errorf("GetVersion() = %q, expected a non-empty fallback version", got)
	}
}

func TestPrintVersion_noPanic(t *testing.T) {
	orig := Version
	defer func() { Version = orig }()

	Version = "v0.0.0-test"
	// printVersion writes to stdout; we just verify it doesn't panic.
	printVersion()
}
