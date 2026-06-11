//go:build darwin

package collector

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// maxOSLogEntries caps how many unified-log entries are read per Collect cycle.
const maxOSLogEntries = 1000

// macLogShowTimeLayout is the timestamp format accepted by `log show --start`.
const macLogShowTimeLayout = "2006-01-02 15:04:05"

// macOS file-based log sources.
var macLogFiles = []struct {
	path   string
	source string
}{
	{"/var/log/system.log", "system.log"},
	{"/var/log/install.log", "install.log"},
}

const crashReportDir = "/Library/Logs/DiagnosticReports"

type darwinCollector struct {
	// open starts a subprocess and streams its stdout. Defaults to execStream;
	// tests inject a fake that returns canned `log show` output.
	open streamOpener
}

// NewCollector creates a macOS-specific log collector. It reads the unified log
// by shelling out to `log show --style ndjson` (pure Go, no cgo), tails the
// classic /var/log files, and scans crash reports. This keeps the agent a
// static, cross-compilable binary built with CGO_ENABLED=0.
func NewCollector() Collector {
	return &darwinCollector{open: execStream}
}

// Sources returns the list of log sources available on macOS.
func (c *darwinCollector) Sources() []string {
	sources := []string{"oslog"}
	for _, lf := range macLogFiles {
		if _, err := os.Stat(lf.path); err == nil {
			sources = append(sources, lf.source)
		}
	}
	if _, err := os.Stat(crashReportDir); err == nil {
		sources = append(sources, "crash_reports")
	}
	return sources
}

// Collect performs batch collection from the unified log, file logs, and crash reports.
func (c *darwinCollector) Collect(ctx context.Context, checkpoint CheckpointData) ([]RawLogEntry, CheckpointData, error) {
	if checkpoint == nil {
		checkpoint = make(CheckpointData)
	}

	newCP := make(CheckpointData)
	for k, v := range checkpoint {
		newCP[k] = v
	}

	var allEntries []RawLogEntry

	// 1. Collect from the unified log via `log show`.
	oslogEntries, oslogCP, err := c.collectOSLog(ctx, checkpoint)
	if err != nil {
		log.Printf("[collector/darwin] OSLog collection error: %v", err)
	} else {
		allEntries = append(allEntries, oslogEntries...)
		for k, v := range oslogCP {
			newCP[k] = v
		}
	}

	// 2. Collect from file-based logs.
	for _, lf := range macLogFiles {
		if ctx.Err() != nil {
			break
		}
		entries, fileCP, err := c.collectFile(ctx, lf.path, lf.source, checkpoint)
		if err != nil {
			log.Printf("[collector/darwin] file %s error: %v", lf.path, err)
			continue
		}
		allEntries = append(allEntries, entries...)
		for k, v := range fileCP {
			newCP[k] = v
		}
	}

	// 3. Collect crash reports.
	if ctx.Err() == nil {
		crashEntries, crashCP, err := c.collectCrashReports(ctx, checkpoint)
		if err != nil {
			log.Printf("[collector/darwin] crash reports error: %v", err)
		} else {
			allEntries = append(allEntries, crashEntries...)
			for k, v := range crashCP {
				newCP[k] = v
			}
		}
	}

	return allEntries, newCP, nil
}

// Subscribe has no real-time path on macOS; events are collected via polling in
// Collect() at the configured flush interval. Returns nil immediately.
func (c *darwinCollector) Subscribe(_ context.Context, _ chan<- RawLogEntry) error {
	return nil
}

// collectOSLog reads entries from the unified log via `log show`, resuming from
// the saved timestamp checkpoint when present, otherwise from a one-hour lookback.
func (c *darwinCollector) collectOSLog(ctx context.Context, checkpoint CheckpointData) ([]RawLogEntry, CheckpointData, error) {
	start := time.Now().Add(-1 * time.Hour)
	if ts, ok := CheckpointFloat64(checkpoint, "oslog_timestamp"); ok && ts > 0 {
		// Resume just after the last entry we saw to avoid re-reading it.
		start = time.Unix(int64(ts), 0).Add(1 * time.Second)
	}

	args := []string{
		"show",
		"--style", "ndjson",
		"--info",
		"--start", start.Format(macLogShowTimeLayout),
	}

	rc, err := c.open(ctx, "log", args...)
	if err != nil {
		return nil, nil, fmt.Errorf("open log show: %w", err)
	}
	defer func() { _ = rc.Close() }()

	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	var entries []RawLogEntry
	var latestUnix int64

	for scanner.Scan() {
		if len(entries) >= maxOSLogEntries || ctx.Err() != nil {
			break
		}
		entry, ok := parseMacLogShowLine(scanner.Bytes())
		if !ok {
			continue
		}
		entries = append(entries, entry)
		if u := entry.Timestamp.Unix(); u > latestUnix {
			latestUnix = u
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("log show scanner: %w", err)
	}

	newCP := CheckpointData{}
	if latestUnix > 0 {
		newCP["oslog_timestamp"] = float64(latestUnix)
	}

	return entries, newCP, nil
}

// collectFile reads new lines from a file-based log starting at the saved offset.
func (c *darwinCollector) collectFile(_ context.Context, path, source string, checkpoint CheckpointData) ([]RawLogEntry, CheckpointData, error) {
	// #nosec G304 - path is a controlled internal parameter
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}

	cpKey := source + "_offset"
	var offset int64

	// Tolerant read: the offset is stored as an int64 in memory and as a
	// float64 after JSON persistence. A bare .(float64) silently failed on the
	// in-memory path, resetting the offset to 0 and re-reading the same lines
	// every cycle.
	if saved, ok := CheckpointInt64(checkpoint, cpKey); ok {
		offset = saved
	}

	// Check for file truncation/rotation
	if offset > info.Size() {
		offset = 0
	}

	if offset >= info.Size() {
		return nil, nil, nil
	}

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, nil, err
	}

	var entries []RawLogEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 256*1024)

	maxLines := 1000
	count := 0

	for scanner.Scan() && count < maxLines {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		entries = append(entries, RawLogEntry{
			Timestamp:  parseMacFileTimestamp(line),
			Source:     source,
			RawMessage: line,
			Severity:   inferMacSeverity(line),
			Metadata:   make(map[string]string),
		})
		count++
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan %s: %w", path, err)
	}

	newOffset, _ := f.Seek(0, io.SeekCurrent)
	return entries, CheckpointData{cpKey: newOffset}, nil
}

// collectCrashReports reads recent crash report files.
func (c *darwinCollector) collectCrashReports(_ context.Context, checkpoint CheckpointData) ([]RawLogEntry, CheckpointData, error) {
	dirEntries, err := os.ReadDir(crashReportDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}

	var lastProcessed float64
	if ts, ok := CheckpointFloat64(checkpoint, "crash_reports_timestamp"); ok {
		lastProcessed = ts
	}

	var entries []RawLogEntry
	var latestMod float64

	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}

		ext := filepath.Ext(de.Name())
		if ext != ".crash" && ext != ".ips" && ext != ".diag" {
			continue
		}

		info, err := de.Info()
		if err != nil {
			continue
		}

		modTime := float64(info.ModTime().Unix())
		if modTime <= lastProcessed {
			continue
		}

		// Read first 4KB of crash report for summary
		path := filepath.Join(crashReportDir, de.Name())
		content, err := readFileHead(path, 4096)
		if err != nil {
			continue
		}

		entries = append(entries, RawLogEntry{
			Timestamp:  info.ModTime(),
			Source:     "crash_reports",
			EventID:    de.Name(),
			RawMessage: content,
			Severity:   "2", // critical
			Metadata: map[string]string{
				"filename": de.Name(),
				"size":     fmt.Sprintf("%d", info.Size()),
			},
		})

		if modTime > latestMod {
			latestMod = modTime
		}

		if len(entries) >= 50 {
			break
		}
	}

	newCP := CheckpointData{}
	if latestMod > 0 {
		newCP["crash_reports_timestamp"] = latestMod
	}

	return entries, newCP, nil
}

func readFileHead(path string, maxBytes int) (string, error) {
	// #nosec G304 - path is built from a controlled directory listing
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, maxBytes)
	n, _ := f.Read(buf)
	return string(buf[:n]), nil
}
