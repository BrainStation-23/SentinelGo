//go:build linux

package collector

// These tests run only on Linux (the OS the linuxCollector targets). They never
// invoke real journalctl: the `open` seam is replaced with a fake that returns
// canned output, so Collect/collectJournal are tested deterministically and
// offline. File tailing is tested against real temp files.

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeOpen returns a streamOpener that yields the given data and records the
// command line it was invoked with.
func fakeOpen(data string, gotArgs *[]string) streamOpener {
	return func(_ context.Context, name string, args ...string) (io.ReadCloser, error) {
		if gotArgs != nil {
			*gotArgs = append([]string{name}, args...)
		}
		return io.NopCloser(strings.NewReader(data)), nil
	}
}

func TestLinuxCollectJournal(t *testing.T) {
	lines := strings.Join([]string{
		`{"__REALTIME_TIMESTAMP":"1700000000000000","__CURSOR":"c1","MESSAGE":"first","PRIORITY":"6"}`,
		`{"__REALTIME_TIMESTAMP":"1700000001000000","__CURSOR":"c2","MESSAGE":"second","PRIORITY":"3"}`,
	}, "\n")

	c := &linuxCollector{open: fakeOpen(lines, nil)}
	entries, cp, err := c.collectJournal(context.Background(), CheckpointData{})
	if err != nil {
		t.Fatalf("collectJournal error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].RawMessage != "first" || entries[1].RawMessage != "second" {
		t.Errorf("unexpected messages: %q, %q", entries[0].RawMessage, entries[1].RawMessage)
	}
	if cp["journal_cursor"] != "c2" {
		t.Errorf("journal_cursor = %v, want c2", cp["journal_cursor"])
	}
}

func TestLinuxCollectJournal_ResumesFromCursor(t *testing.T) {
	var gotArgs []string
	c := &linuxCollector{open: fakeOpen("", &gotArgs)}
	_, _, err := c.collectJournal(context.Background(), CheckpointData{"journal_cursor": "prev-cursor"})
	if err != nil {
		t.Fatalf("collectJournal error: %v", err)
	}
	joined := strings.Join(gotArgs, " ")
	if !strings.Contains(joined, "--after-cursor prev-cursor") {
		t.Errorf("expected --after-cursor prev-cursor in args, got: %s", joined)
	}
}

func TestLinuxCollectJournal_OpenError(t *testing.T) {
	c := &linuxCollector{open: func(_ context.Context, _ string, _ ...string) (io.ReadCloser, error) {
		return nil, fmt.Errorf("journalctl not found")
	}}
	if _, _, err := c.collectJournal(context.Background(), CheckpointData{}); err == nil {
		t.Error("expected error when open fails")
	}
}

func TestLinuxCollect_DegradesWhenJournalFails(t *testing.T) {
	// Collect() should not fail outright when the journal source errors; it logs
	// and continues with whatever file sources produce.
	c := &linuxCollector{open: func(_ context.Context, _ string, _ ...string) (io.ReadCloser, error) {
		return nil, fmt.Errorf("boom")
	}}
	if _, _, err := c.Collect(context.Background(), CheckpointData{}); err != nil {
		t.Errorf("Collect should degrade gracefully, got error: %v", err)
	}
}

func TestLinuxCollectFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	content := "Jan  2 15:04:05 host sshd[1]: connection error\n" +
		"Jan  2 15:04:06 host sshd[1]: routine message\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write temp log: %v", err)
	}

	c := &linuxCollector{}
	entries, cp, err := c.collectFile(context.Background(), path, "auth.log", CheckpointData{})
	if err != nil {
		t.Fatalf("collectFile error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Severity != "3" {
		t.Errorf("first line severity = %q, want 3 (error)", entries[0].Severity)
	}
	if _, ok := cp["auth.log_offset"]; !ok {
		t.Error("expected auth.log_offset in checkpoint")
	}

	// A second read from the saved checkpoint should yield nothing new.
	entries2, _, err := c.collectFile(context.Background(), path, "auth.log", cp)
	if err != nil {
		t.Fatalf("second collectFile error: %v", err)
	}
	if len(entries2) != 0 {
		t.Errorf("expected 0 new entries on re-read, got %d", len(entries2))
	}
}

func TestLinuxSources(t *testing.T) {
	sources := NewCollector().Sources()
	found := false
	for _, s := range sources {
		if s == "journal" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'journal' in sources, got %v", sources)
	}
}
