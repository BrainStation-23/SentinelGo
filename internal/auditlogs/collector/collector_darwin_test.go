//go:build darwin

package collector

// These tests run only on macOS (the OS the darwinCollector targets). They never
// invoke real `log show`: the `open` seam is replaced with a fake returning
// canned ndjson, so collectOSLog is tested deterministically and offline.

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeOpen(data string, gotArgs *[]string) streamOpener {
	return func(_ context.Context, name string, args ...string) (io.ReadCloser, error) {
		if gotArgs != nil {
			*gotArgs = append([]string{name}, args...)
		}
		return io.NopCloser(strings.NewReader(data)), nil
	}
}

func TestDarwinCollectOSLog(t *testing.T) {
	lines := strings.Join([]string{
		`{"timestamp":"2024-04-19 14:30:00.000000-0700","messageType":"Error","eventMessage":"boom"}`,
		`{"metadataLineWithNoMessage":true}`, // should be skipped
		`{"timestamp":"2024-04-19 14:30:01.000000-0700","messageType":"Info","eventMessage":"ok"}`,
	}, "\n")

	c := &darwinCollector{open: fakeOpen(lines, nil)}
	entries, cp, err := c.collectOSLog(context.Background(), CheckpointData{})
	if err != nil {
		t.Fatalf("collectOSLog error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2 (one non-entry line skipped)", len(entries))
	}
	if entries[0].RawMessage != "boom" || entries[0].Severity != "3" {
		t.Errorf("unexpected first entry: %+v", entries[0])
	}
	if _, ok := cp["oslog_timestamp"].(float64); !ok {
		t.Errorf("expected oslog_timestamp checkpoint, got %v", cp["oslog_timestamp"])
	}
}

func TestDarwinCollectOSLog_StartFromCheckpoint(t *testing.T) {
	var gotArgs []string
	c := &darwinCollector{open: fakeOpen("", &gotArgs)}
	_, _, err := c.collectOSLog(context.Background(), CheckpointData{"oslog_timestamp": float64(1700000000)})
	if err != nil {
		t.Fatalf("collectOSLog error: %v", err)
	}
	joined := strings.Join(gotArgs, " ")
	if !strings.Contains(joined, "--start") {
		t.Errorf("expected --start in log show args, got: %s", joined)
	}
}

func TestDarwinCollectOSLog_OpenError(t *testing.T) {
	c := &darwinCollector{open: func(_ context.Context, _ string, _ ...string) (io.ReadCloser, error) {
		return nil, fmt.Errorf("log not found")
	}}
	if _, _, err := c.collectOSLog(context.Background(), CheckpointData{}); err == nil {
		t.Error("expected error when open fails")
	}
}

func TestDarwinCollectFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "system.log")
	content := "Apr 19 14:30:00 host kernel: mount failed\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write temp log: %v", err)
	}

	c := &darwinCollector{}
	entries, _, err := c.collectFile(context.Background(), path, "system.log", CheckpointData{})
	if err != nil {
		t.Fatalf("collectFile error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].Severity != "3" {
		t.Errorf("severity = %q, want 3 (failed)", entries[0].Severity)
	}
}

func TestDarwinSources(t *testing.T) {
	sources := NewCollector().Sources()
	if len(sources) == 0 || sources[0] != "oslog" {
		t.Errorf("expected 'oslog' first in sources, got %v", sources)
	}
}
