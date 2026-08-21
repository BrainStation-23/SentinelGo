//go:build windows

package persistence

import (
	"context"
	"errors"
	"strings"

	"golang.org/x/sys/windows/registry"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

// runKeyPaths are the two machine-wide auto-run registry locations this
// pass covers — see the package doc for why per-user HKCU/HKEY_USERS run
// keys are deferred.
var runKeyPaths = []struct {
	path string
	name string
}{
	{`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "HKLM\\...\\Run"},
	{`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "HKLM\\...\\RunOnce"},
}

func platformEntries(ctx context.Context, cfg tel.CollectorConfig) signal {
	var entries []Entry
	var warnings []string
	var sources []string

	for _, rk := range runKeyPaths {
		vals, err := readRunKey(rk.path)
		if err != nil {
			warnings = append(warnings, rk.name+" registry read failed")
			continue
		}
		entries = append(entries, vals...)
		sources = append(sources, "registry:"+rk.name)
	}

	tasks, err := readScheduledTasks(ctx, cfg.IncludeBuiltinScheduledTasks)
	if err != nil {
		warnings = append(warnings, "Get-ScheduledTask query failed")
	} else {
		entries = append(entries, tasks...)
		sources = append(sources, "powershell:Get-ScheduledTask")
	}

	return signal{Entries: entries, Source: strings.Join(sources, ", "), Warnings: warnings}
}

func readRunKey(path string) ([]Entry, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		if errIsNotExist(err) {
			return nil, nil // the key simply does not exist; not a failure
		}
		return nil, err
	}
	defer k.Close()

	names, err := k.ReadValueNames(-1)
	if err != nil {
		return nil, err
	}

	entries := make([]Entry, 0, len(names))
	for _, name := range names {
		val, _, err := k.GetStringValue(name)
		if err != nil {
			continue
		}
		entries = append(entries, Entry{
			Type:     "registry_run_key",
			Name:     name,
			Command:  val,
			Location: `HKLM\` + path,
		})
	}
	return entries, nil
}

func errIsNotExist(err error) bool {
	return errors.Is(err, registry.ErrNotExist)
}

// scheduledTaskScript reports Name, Path, Command and Enabled. When
// includeBuiltin is false, tasks under \Microsoft\Windows\* are excluded —
// docs/telemetry/03-collection-matrix.md notes this filter cuts a typical
// ~400-task list down to ~30, and CollectorConfig.IncludeBuiltinScheduledTasks
// defaults to false for exactly that reason.
func scheduledTaskScript(includeBuiltin bool) string {
	filter := ""
	if !includeBuiltin {
		filter = " | Where-Object { $_.TaskPath -notlike '\\Microsoft\\Windows\\*' }"
	}
	return `Get-ScheduledTask` + filter + ` | ForEach-Object {
	$action = $_.Actions | Select-Object -First 1
	[PSCustomObject]@{
		Name = ''+$_.TaskName
		Path = ''+$_.TaskPath
		Command = if ($action) { ''+$action.Execute } else { '' }
		Enabled = $_.State -ne 'Disabled'
	}
} | ConvertTo-Json -Compress`
}

func readScheduledTasks(_ context.Context, includeBuiltin bool) ([]Entry, error) {
	out, err := shared.RunCommand("powershell", "-NoProfile", "-Command", scheduledTaskScript(includeBuiltin))
	if err != nil {
		return nil, err
	}
	rows, err := parseWindowsTasks(out)
	if err != nil {
		return nil, err
	}

	entries := make([]Entry, 0, len(rows))
	for _, r := range rows {
		enabled := r.Enabled
		entries = append(entries, Entry{
			Type:     "scheduled_task",
			Name:     r.Name,
			Command:  r.Command,
			Location: r.Path,
			Enabled:  &enabled,
		})
	}
	return entries, nil
}
