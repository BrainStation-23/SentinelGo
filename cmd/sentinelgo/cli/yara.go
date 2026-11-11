package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/yara"
	"sentinelgo/internal/yara/scan"
)

// YARACommand is `sentinelgo yara status`: threat hunting on this device,
// for support (#417).
const YARACommand = "yara"

// RunYARA runs `sentinelgo yara status [-json] [-config PATH]` and returns
// the exit code. It reads the status the service last wrote and never
// contacts the backend. It prints rule and ruleset names, versions and
// counts, never rule text.
func RunYARA(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "status" {
		_, _ = fmt.Fprintln(stderr, "usage: sentinelgo yara status [-json] [-config PATH]")
		return 2
	}
	fset := flag.NewFlagSet("yara status", flag.ContinueOnError)
	fset.SetOutput(stderr)
	cfgPath := fset.String("config", "", "config.json of the install to inspect (default: the standard path)")
	asJSON := fset.Bool("json", false, "print JSON")
	if err := fset.Parse(args[1:]); err != nil {
		return 2
	}
	load := loadDefaultConfig
	if *cfgPath != "" {
		load = func() (*config.Config, error) { return config.Load(*cfgPath) }
	}
	cfg, err := load()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Failed to load config: %v\n", err)
		return 1
	}
	path := filepath.Join(filepath.Dir(cfg.Path), scan.StatusFileName)
	ls, err := scan.ReadStatus(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		_, _ = fmt.Fprintln(stderr, "No threat hunting status yet: the service hasn't started threat hunting on this device (is it running this version?).")
		return 1
	case errors.Is(err, fs.ErrPermission):
		_, _ = fmt.Fprintln(stderr, "Cannot read the threat hunting status: run as Administrator / root.")
		return 1
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "Cannot read the threat hunting status: %v\n", err)
		return 1
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(ls); err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	printYARAStatus(stdout, ls, cfg.YARAEnabled)
	return 0
}

func printYARAStatus(w io.Writer, ls *scan.LocalStatus, configEnabled bool) {
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format+"\n", a...) }
	st := ls.Status
	p("Threat hunting (YARA) status")
	p("============================")
	p("Local switch (yara_enabled): %v", configEnabled)
	if configEnabled != ls.LocalEnabled {
		p("                             (the service runs with %v: restart it to apply the change)", ls.LocalEnabled)
	}
	p("State:                       %s%s", st.State, stateHint(st.State))
	if st.AppliedVersion != "" {
		p("Applied bundle version:      %s", st.AppliedVersion)
	} else {
		p("Applied bundle version:      none")
	}
	p("Engine / agent version:      %s / %s", st.EngineVersion, st.AgentVersion)
	sum := yara.SummaryOf(st)
	p("Rulesets:                    %d (%d rules compiled, %d skipped)", sum.Rulesets, sum.CompiledRules, sum.SkippedRules)
	for _, r := range st.Rulesets {
		p("  - %s r%d: %d rules", r.ID, r.Revision, r.CompiledRules)
		for _, s := range r.SkippedRules {
			if s.Line > 0 {
				p("      skipped %s (line %d): %s", s.Rule, s.Line, s.Reason)
			} else {
				p("      skipped %s: %s", s.Rule, s.Reason)
			}
		}
	}
	if wk := ls.Workers; wk != nil {
		health := "healthy"
		if wk.Disabled {
			health = "DISABLED after repeated crashes (restart the service)"
		}
		p("Scan workers:                %d running, sandbox %q, %d failures, %s", wk.Live, wk.Sandbox, wk.Failures, health)
	}
	if r := ls.Scanning; r != nil {
		p("Scanning now:                %s (%s %s, since %s, %d files)", r.ScanID, r.Trigger, r.Preset, r.Started.Format(time.RFC3339), r.Files)
	}
	if s := st.LastScan; s != nil {
		p("Last scan:                   %s %s (%s %s)", s.ScanID, s.State, s.Trigger, s.Preset)
		p("                             finished %s: %d scanned, %d skipped, %d errors, %d matches",
			s.FinishedAt.Format(time.RFC3339), s.FilesScanned, s.FilesSkipped, s.Errors, s.Matches)
	} else {
		p("Last scan:                   none")
	}
	for _, s := range ls.Schedules {
		line := fmt.Sprintf("  schedule %s: %s every %dh", s.ID, s.Preset, s.EveryHours)
		if !s.LastRun.IsZero() {
			line += ", last run " + s.LastRun.Format(time.RFC3339)
		}
		if !s.NextRun.IsZero() {
			line += ", next " + s.NextRun.Format(time.RFC3339)
		}
		if s.Resumes {
			line += " (continues where the last scan stopped)"
		}
		p("%s", line)
	}
	printOnWrite(p, ls.OnWrite)
	p("Event queue:                 %d events awaiting upload, %d dropped over the cap", ls.QueuedEvents, ls.DroppedEvents)
	p("Written by the service at:   %s", ls.UpdatedAt.Format(time.RFC3339))
}

// printOnWrite prints on-write scanning (#418): counts and the window's
// scan id, never paths.
func printOnWrite(p func(string, ...any), ow *scan.OnWriteStatus) {
	if ow == nil {
		p("On-write scanning:           off")
		return
	}
	if ow.Watching > 0 {
		p("On-write scanning:           on, %d folders watched, %d files waiting", ow.Watching, ow.Pending)
	} else {
		p("On-write scanning:           NOT WATCHING (the service retries every minute)")
	}
	if ow.Error != "" {
		p("                             watcher error: %s", ow.Error)
	}
	if ow.Dropped > 0 || ow.Lost > 0 {
		p("                             %d files dropped (too many waiting), notifications lost %d times; the next scheduled scan covers them", ow.Dropped, ow.Lost)
	}
	if w := ow.Window; w != nil {
		p("                             window %s since %s: %d scanned, %d skipped, %d errors, %d matches",
			w.ScanID, w.Started.Format(time.RFC3339), w.Scanned, w.Skipped, w.Errors, w.Matches)
	}
}

// stateHint explains the states support asks about.
func stateHint(state string) string {
	switch state {
	case yara.StateDisabled:
		return " (yara_enabled is false, or threat hunting is off for this device in the console)"
	case yara.StateTCCDenied:
		return " (macOS: grant SentinelGo Full Disk Access, e.g. with the MDM profile)"
	case yara.StateWorkerUnavailable:
		return " (scan workers keep crashing; see the service log)"
	case yara.StateCompileFailed, yara.StateDownloadFailed:
		return " (the last good rules stay in force; see the service log)"
	}
	return ""
}
