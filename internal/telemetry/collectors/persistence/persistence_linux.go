//go:build linux

package persistence

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

func platformEntries(ctx context.Context, _ tel.CollectorConfig) signal {
	var entries []Entry
	var warnings []string
	var sources []string

	out, _, err := shared.RunCommandOutputContext(ctx, "systemctl", "show", "*.service",
		"-p", "Id", "-p", "ExecStart", "-p", "FragmentPath", "-p", "UnitFileState")
	if err != nil {
		warnings = append(warnings, "systemctl show failed to run")
	} else {
		entries = append(entries, parseSystemctlShow(out)...)
		sources = append(sources, "exec:systemctl")
	}

	cronEntries, cronSources := readCronEntries()
	entries = append(entries, cronEntries...)
	sources = append(sources, cronSources...)

	return signal{Entries: entries, Source: strings.Join(sources, ", "), Warnings: warnings}
}

// readCronEntries reads every crontab-family location this pass covers:
// /etc/crontab and /etc/cron.d/* (system format, with a user field), and
// each per-user spool file under /var/spool/cron (or
// /var/spool/cron/crontabs on Debian-family systems) in the per-user format.
func readCronEntries() ([]Entry, []string) {
	var entries []Entry
	var sources []string

	if content, err := shared.ReadFileContent("/etc/crontab"); err == nil {
		entries = append(entries, parseCrontab(content, true, "/etc/crontab")...)
		sources = append(sources, "file:/etc/crontab")
	}

	if dirEntries, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, de := range dirEntries {
			if de.IsDir() {
				continue
			}
			path := filepath.Join("/etc/cron.d", de.Name())
			if content, err := shared.ReadFileContent(path); err == nil {
				entries = append(entries, parseCrontab(content, true, path)...)
			}
		}
		sources = append(sources, "dir:/etc/cron.d")
	}

	for _, spoolDir := range []string{"/var/spool/cron/crontabs", "/var/spool/cron"} {
		dirEntries, err := os.ReadDir(spoolDir)
		if err != nil {
			continue
		}
		for _, de := range dirEntries {
			if de.IsDir() {
				continue
			}
			path := filepath.Join(spoolDir, de.Name())
			if content, err := shared.ReadFileContent(path); err == nil {
				entries = append(entries, parseCrontab(content, false, path)...)
			}
		}
		sources = append(sources, "dir:"+spoolDir)
		break // the two paths are alternate names for the same thing; use whichever exists first
	}

	return entries, sources
}
