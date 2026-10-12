package main

import (
	"io"
	"os"
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

func TestPrintVersion_ListsCapabilities(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	printVersion()
	os.Stdout = orig
	_ = w.Close()
	out, _ := io.ReadAll(r)

	if !strings.Contains(string(out), "Capabilities: script_inline_body_v1, task_artifacts_v1") {
		t.Errorf("printVersion output = %q, want the capabilities line", out)
	}
}
