package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/dlp/channel/clipboard"
	"sentinelgo/internal/dlp/detect"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
	"sentinelgo/internal/store"
)

// DLPCommand is `sentinelgo dlp status|test`.
const DLPCommand = "dlp"

// maxTestInput bounds what `dlp test` reads.
const maxTestInput = 16 << 20

// DLPStatus is what `dlp status` (and -debug-dump) reports. It never holds
// scanned content.
type DLPStatus struct {
	LocalEnabled       bool              `json:"local_enabled"`
	Policy             *DLPPolicyStatus  `json:"policy"`
	DetectorsSupported int               `json:"detectors_supported"`
	Capabilities       map[string]string `json:"capabilities"`
	Queue              *DLPQueueStatus   `json:"queue,omitempty"`
	Errors             []string          `json:"errors,omitempty"`
}

// DLPPolicyStatus describes the cached bundle.
type DLPPolicyStatus struct {
	Version       string                `json:"version"`
	Enabled       bool                  `json:"enabled"`
	CachedAt      time.Time             `json:"cached_at"`
	EvidenceMode  string                `json:"evidence_mode"`
	PollInterval  string                `json:"poll_interval"`
	Clipboard     bool                  `json:"clipboard_enabled"`
	Policies      []DLPPolicySummary    `json:"policies"`
	CompileErrors []detect.CompileError `json:"compile_errors,omitempty"`
}

// DLPPolicySummary is one policy, without its patterns or keywords.
type DLPPolicySummary struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Action   string   `json:"action"`
	Severity string   `json:"severity"`
	Channels []string `json:"channels"`
	Rules    int      `json:"rules"`
}

// DLPQueueStatus is the evidence queue awaiting upload.
type DLPQueueStatus struct {
	Events  int   `json:"events"`
	Bytes   int64 `json:"bytes"`
	Dropped int64 `json:"dropped"`
}

// dlpDir is where the service keeps DLP state (next to config.json).
func dlpDir(cfg *config.Config) string { return filepath.Dir(cfg.Path) }

// dlpStatus reads the local DLP state. It works offline and never contacts
// the backend; problems are listed in Errors rather than failing.
func dlpStatus(cfg *config.Config) DLPStatus {
	st := DLPStatus{
		LocalEnabled:       cfg.DLPEnabled,
		DetectorsSupported: len(detect.SupportedDetectors()),
		Capabilities:       map[string]string{policy.ChannelClipboard: clipboard.New().Supported().String()},
	}
	cachePath := filepath.Join(dlpDir(cfg), policy.CacheFileName)
	b, err := policy.NewCache(cachePath).Load()
	if err != nil {
		st.Errors = append(st.Errors, err.Error())
	}
	if b != nil {
		ps := &DLPPolicyStatus{
			Version: b.Version, Enabled: b.Enabled, EvidenceMode: b.EvidenceMode,
			PollInterval: b.PollInterval().String(), Clipboard: b.Modules.Clipboard.Enabled,
			CompileErrors: policy.Compile(b).CompileErrors,
		}
		if fi, err := os.Stat(cachePath); err == nil {
			ps.CachedAt = fi.ModTime().UTC()
		}
		for _, p := range b.Policies {
			ps.Policies = append(ps.Policies, DLPPolicySummary{
				ID: p.ID, Name: p.Name, Action: p.Action, Severity: p.Severity, Channels: p.Channels, Rules: len(p.Detectors),
			})
		}
		st.Policy = ps
	}

	dbPath := filepath.Join(dlpDir(cfg), store.DLPEventsDBName)
	if _, err := os.Stat(dbPath); err == nil {
		q, err := store.NewDLPEventStore(dbPath)
		if err != nil {
			st.Errors = append(st.Errors, err.Error())
		} else {
			defer func() { _ = q.Close() }()
			rows, bytes, dropped, err := q.Stats()
			if err != nil {
				st.Errors = append(st.Errors, err.Error())
			}
			st.Queue = &DLPQueueStatus{Events: rows, Bytes: bytes, Dropped: dropped}
		}
	}
	return st
}

// RunDLP runs `sentinelgo dlp <status|test> …` and returns the exit code.
// -config points at a non-default install's config.json.
func RunDLP(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "status" && args[0] != "test") {
		_, _ = fmt.Fprintln(stderr, "usage: sentinelgo dlp status [-json] [-config PATH] | sentinelgo dlp test [-file PATH|-] [-config PATH]")
		return 2
	}
	fs := flag.NewFlagSet("dlp "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "config.json of the install to inspect (default: the standard path)")
	asJSON := fs.Bool("json", false, "print JSON (status)")
	file := fs.String("file", "-", "file to scan, or - for stdin (test)")
	if err := fs.Parse(args[1:]); err != nil {
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
	if args[0] == "test" {
		return dlpTest(cfg, *file, stdin, stdout, stderr)
	}
	st := dlpStatus(cfg)
	if *asJSON {
		data, _ := json.MarshalIndent(st, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
	} else {
		printDLPStatus(stdout, st)
	}
	return 0
}

func printDLPStatus(w io.Writer, st DLPStatus) {
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format+"\n", a...) }
	p("DLP Status")
	p("==========")
	p("Local switch (dlp_enabled): %v", st.LocalEnabled)
	p("Detectors supported:        %d", st.DetectorsSupported)
	for _, ch := range sortedKeys(st.Capabilities) {
		p("Channel %-19s %s", ch+":", st.Capabilities[ch])
	}
	if st.Policy == nil {
		p("Policy:                     none cached (DLP stays off until the server sends one)")
	} else {
		ps := st.Policy
		p("Policy version:             %s", ps.Version)
		p("Org switch (enabled):       %v (clipboard module: %v)", ps.Enabled, ps.Clipboard)
		if !ps.CachedAt.IsZero() {
			p("Cached at:                  %s (%s ago)", ps.CachedAt.Format(time.RFC3339), time.Since(ps.CachedAt).Round(time.Second))
		}
		p("Evidence mode / poll:       %s / %s", ps.EvidenceMode, ps.PollInterval)
		p("Policies:                   %d", len(ps.Policies))
		for _, pol := range ps.Policies {
			p("  - %s [%s, %s] on %s, %d rules", pol.Name, pol.Action, pol.Severity, strings.Join(pol.Channels, ","), pol.Rules)
		}
		for _, ce := range ps.CompileErrors {
			p("  ! rule %s skipped: %s", ce.RuleID, ce.Error)
		}
	}
	if st.Queue != nil {
		p("Evidence queue:             %d events (%d bytes), %d dropped over the cap", st.Queue.Events, st.Queue.Bytes, st.Queue.Dropped)
	}
	p("Session helpers:            see the service log (\"session helper connected\")")
	for _, e := range st.Errors {
		p("Error: %s", e)
	}
}

// dlpTest runs the cached policy over text and prints what would happen,
// with masked findings only.
func dlpTest(cfg *config.Config, file string, stdin io.Reader, stdout, stderr io.Writer) int {
	b, err := policy.NewCache(filepath.Join(dlpDir(cfg), policy.CacheFileName)).Load()
	switch {
	case errors.Is(err, fs.ErrPermission):
		_, _ = fmt.Fprintln(stderr, "Cannot read the cached policy: run as Administrator / root.")
		return 1
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "Cannot read the cached policy: %v\n", err)
		return 1
	case b == nil:
		_, _ = fmt.Fprintln(stderr, "No policy cached yet: the agent hasn't received one from the server.")
		return 1
	}

	in := stdin
	if file != "-" {
		f, err := os.Open(file) // #nosec G304 -- the operator names the file to scan
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "open %s: %v\n", file, err)
			return 1
		}
		defer func() { _ = f.Close() }()
		in = f
	}
	data, err := io.ReadAll(io.LimitReader(in, maxTestInput))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "read input: %v\n", err)
		return 1
	}

	c := policy.Compile(b)
	names := map[string]string{}
	for _, p := range b.Policies {
		names[p.ID] = p.Name
	}
	d := clipboard.Decide(c, string(data), events.SourceApp{}, time.Now())
	r := testReport{bundle: b, decision: d, names: names, inputLen: len(data), scanned: len(data),
		offReason: enforcementOff(cfg.DLPEnabled, b)}
	if c.Clipboard != nil {
		res := c.Clipboard.Scan(string(data))
		r.scanned, r.truncated = res.ScannedBytes, res.Truncated
	}
	printDecision(stdout, r)
	return 0
}

// testReport is what dlp test prints about one run.
type testReport struct {
	bundle    *policy.Bundle
	decision  clipboard.Decision
	names     map[string]string // policy id -> name
	inputLen  int
	scanned   int
	truncated bool
	offReason string // why nothing would be enforced on this device, if so
}

// enforcementOff says why the device enforces nothing, or "".
func enforcementOff(localEnabled bool, b *policy.Bundle) string {
	switch {
	case !localEnabled:
		return "DLP is off on this device (dlp_enabled: false in config.json)"
	case !b.Enabled:
		return "DLP is switched off for this device by the server (enabled: false)"
	case !b.Modules.Clipboard.Enabled:
		return "the clipboard module is switched off (modules.clipboard.enabled: false)"
	}
	return ""
}

func printDecision(w io.Writer, r testReport) {
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format+"\n", a...) }
	p("Policy %s: %d of %d bytes scanned against the clipboard policies", r.bundle.Version, r.scanned, r.inputLen)
	if r.truncated {
		p("Note: only the first %d bytes are scanned (max_scan_bytes); anything after them is not checked.", r.scanned)
	}
	d := r.decision
	if len(d.Events) == 0 {
		p("No policy matched.")
	} else {
		for _, ev := range d.Events {
			p("Matched %q (%s, severity %s)", r.names[ev.PolicyID], ev.Action, ev.Severity)
			for _, f := range ev.Findings {
				p("  %-32s x%-3d %s", f.Detector, f.Count, f.Masked)
			}
		}
		if d.Block {
			p("Policy outcome: BLOCK. The clipboard would read: %q", d.Message)
		} else {
			p("Policy outcome: MONITOR (recorded, not blocked)")
		}
	}
	if r.offReason != "" {
		p("On this device nothing is enforced: %s.", r.offReason)
	}
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
