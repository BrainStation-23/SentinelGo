//go:build darwin

package persistence

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

// launchdDirs are scanned for job plists. System-level LaunchDaemons/Agents
// only in this pass — per-user ~/Library/LaunchAgents would need the same
// per-user enumeration the package doc defers for Windows run keys.
var launchdDirs = []string{
	"/Library/LaunchAgents",
	"/Library/LaunchDaemons",
}

func platformEntries(ctx context.Context, _ tel.CollectorConfig) signal {
	var entries []Entry
	var warnings []string
	var sources []string

	for _, dir := range launchdDirs {
		dirEntries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, de := range dirEntries {
			if de.IsDir() || !strings.HasSuffix(de.Name(), ".plist") {
				continue
			}
			path := filepath.Join(dir, de.Name())
			entry, ok := readLaunchdPlist(ctx, path)
			if !ok || isAppleOwnedLaunchdLabel(entry.Name) {
				continue
			}
			entries = append(entries, entry)
		}
		sources = append(sources, "dir:"+dir)
	}

	if len(sources) == 0 {
		warnings = append(warnings, "no launchd directories were readable")
	}

	return signal{Entries: entries, Source: strings.Join(sources, ", "), Warnings: warnings}
}

// readLaunchdPlist converts one plist to JSON via plutil — plists are
// frequently binary and this module has no plist-decoding dependency, the
// same approach the matrix doc recommends for launchd generally.
func readLaunchdPlist(ctx context.Context, path string) (Entry, bool) {
	out, err := shared.RunCommandContext(ctx, "plutil", "-convert", "json", "-o", "-", path)
	if err != nil {
		return Entry{}, false
	}
	return parseLaunchdPlist(out, path)
}
