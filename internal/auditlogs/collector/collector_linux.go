//go:build linux

package collector

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"syscall"
)

// maxJournalEntries caps how many journal entries are read per Collect cycle.
const maxJournalEntries = 1000

// logFiles are the file-based log sources we tail.
var logFiles = []struct {
	path   string
	source string
}{
	{"/var/log/auth.log", "auth.log"},
	{"/var/log/syslog", "syslog"},
	{"/var/log/messages", "messages"},
	{"/var/log/kern.log", "kern.log"},
}

type linuxCollector struct {
	// open starts a subprocess and streams its stdout. Defaults to execStream;
	// tests inject a fake that returns canned journalctl output.
	open streamOpener
}

// NewCollector creates a Linux-specific log collector. It reads the systemd
// journal by shelling out to `journalctl -o json` (pure Go, no cgo) and tails
// the classic /var/log files directly. This keeps the agent a static,
// cross-compilable binary built with CGO_ENABLED=0.
func NewCollector() Collector {
	return &linuxCollector{open: execStream}
}

// Sources returns the list of log sources available on Linux.
func (c *linuxCollector) Sources() []string {
	sources := []string{"journal"}
	for _, lf := range logFiles {
		if _, err := os.Stat(lf.path); err == nil {
			sources = append(sources, lf.source)
		}
	}
	return sources
}

// Collect performs batch collection from both the systemd journal and file-based logs.
func (c *linuxCollector) Collect(ctx context.Context, checkpoint CheckpointData) ([]RawLogEntry, CheckpointData, error) {
	if checkpoint == nil {
		checkpoint = make(CheckpointData)
	}
	newCP := make(CheckpointData)
	for k, v := range checkpoint {
		newCP[k] = v
	}

	var allEntries []RawLogEntry

	// 1. Collect from the systemd journal via journalctl.
	journalEntries, journalCP, err := c.collectJournal(ctx, checkpoint)
	if err != nil {
		log.Printf("[collector/linux] journal collection error: %v", err)
	} else {
		allEntries = append(allEntries, journalEntries...)
		for k, v := range journalCP {
			newCP[k] = v
		}
	}

	// 2. Collect from file-based logs.
	for _, lf := range logFiles {
		if ctx.Err() != nil {
			break
		}
		fileEntries, fileCP, err := c.collectFile(ctx, lf.path, lf.source, checkpoint)
		if err != nil {
			log.Printf("[collector/linux] file %s collection error: %v", lf.path, err)
			continue
		}
		allEntries = append(allEntries, fileEntries...)
		for k, v := range fileCP {
			newCP[k] = v
		}
	}

	return allEntries, newCP, nil
}

// Subscribe streams high-priority journal entries (priority <= 3: err and above)
// in real time using `journalctl -f`. It blocks until ctx is cancelled, at which
// point the journalctl subprocess is terminated and the method returns nil.
func (c *linuxCollector) Subscribe(ctx context.Context, ch chan<- RawLogEntry) error {
	// -f follow, -n 0 start at the tail (no backlog), -p 3 priority err and above.
	args := []string{"-o", "json", "--no-pager", "-q", "-f", "-n", "0", "-p", "3"}
	rc, err := c.open(ctx, "journalctl", args...)
	if err != nil {
		return fmt.Errorf("open journalctl -f: %w", err)
	}
	defer func() { _ = rc.Close() }()

	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for scanner.Scan() {
		if ctx.Err() != nil {
			return nil
		}
		entry, _, ok := parseJournalLine(scanner.Bytes())
		if !ok {
			continue
		}
		select {
		case ch <- entry:
		case <-ctx.Done():
			return nil
		default:
			// Channel full, drop entry to avoid blocking the follow stream.
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("journalctl -f scanner: %w", err)
	}
	return nil
}

// collectJournal reads journal entries via journalctl, resuming from the saved
// cursor when present, otherwise from a one-hour lookback.
func (c *linuxCollector) collectJournal(ctx context.Context, checkpoint CheckpointData) ([]RawLogEntry, CheckpointData, error) {
	args := []string{"-o", "json", "--no-pager", "-q"}
	if cursor, ok := checkpoint["journal_cursor"].(string); ok && cursor != "" {
		args = append(args, "--after-cursor", cursor)
	} else {
		args = append(args, "--since", "1 hour ago")
	}

	rc, err := c.open(ctx, "journalctl", args...)
	if err != nil {
		return nil, nil, fmt.Errorf("open journalctl: %w", err)
	}
	defer func() { _ = rc.Close() }()

	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	var entries []RawLogEntry
	newCP := make(CheckpointData)

	for scanner.Scan() {
		if len(entries) >= maxJournalEntries || ctx.Err() != nil {
			break
		}
		entry, cursor, ok := parseJournalLine(scanner.Bytes())
		if !ok {
			continue
		}
		entries = append(entries, entry)

		// Track the cursor of the last successfully parsed entry so the next
		// cycle resumes exactly where this one stopped (even if we hit the cap).
		if cursor != "" {
			newCP["journal_cursor"] = cursor
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("journalctl scanner: %w", err)
	}
	return entries, newCP, nil
}

// collectFile reads new lines from a log file starting at the saved offset.
// Detects log rotation via inode comparison.
func (c *linuxCollector) collectFile(ctx context.Context, path, source string, checkpoint CheckpointData) ([]RawLogEntry, CheckpointData, error) {
	// #nosec G304 - path is a controlled internal parameter
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("[collector/linux] error closing file %s: %v", path, err)
		}
	}()

	info, err := f.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("stat %s: %w", path, err)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, nil, fmt.Errorf("cannot get inode for %s", path)
	}

	currentInode := stat.Ino
	cpKey := source + "_offset"
	inodeKey := source + "_inode"

	var offset int64

	// Check for log rotation (inode change). Tolerant accessors are used because
	// checkpoint values are float64 after JSON persistence but may be other
	// numeric types in memory between cycles.
	if savedInode, ok := CheckpointInt64(checkpoint, inodeKey); ok {
		if uint64(savedInode) != currentInode {
			// Log rotated (new inode) -- read from beginning
			offset = 0
		} else if savedOffset, ok := CheckpointInt64(checkpoint, cpKey); ok {
			offset = savedOffset
		}
	}

	// Check for in-place truncation (e.g. logrotate copytruncate): same inode
	// but the file shrank below our saved offset. Reset to the start so we don't
	// wait for the file to grow back past a stale offset (mirrors the darwin path).
	if offset > info.Size() {
		offset = 0
	}

	// Don't read past end of file
	if offset >= info.Size() {
		return nil, nil, nil
	}

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, nil, fmt.Errorf("seek %s: %w", path, err)
	}

	var entries []RawLogEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 256*1024)

	maxLines := 1000
	lineCount := 0

	for scanner.Scan() && lineCount < maxLines {
		if ctx.Err() != nil {
			break
		}

		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		entry := RawLogEntry{
			Timestamp:  parseSyslogTimestamp(line),
			Source:     source,
			RawMessage: line,
			Severity:   inferSyslogSeverity(line),
			Metadata:   make(map[string]string),
		}

		entries = append(entries, entry)
		lineCount++
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan %s: %w", path, err)
	}

	// Update offset to current file position
	newOffset, _ := f.Seek(0, io.SeekCurrent)
	newCP := CheckpointData{
		cpKey:    float64(newOffset),
		inodeKey: float64(currentInode),
	}

	return entries, newCP, nil
}
