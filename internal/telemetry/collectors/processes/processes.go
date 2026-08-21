// Package processes implements the telemetry Process Inventory collector,
// filling the "processes" section.
//
// Collection goes through gopsutil/v4/process exclusively — pure Go, no
// per-OS files needed, per docs/telemetry/03-collection-matrix.md's explicit
// recommendation ("Process inventory | gopsutil/v4/process — pure Go, no
// per-OS files needed"). This is the one C1–E collector without platform
// build tags for that reason.
//
// Command-line capture is off unless CollectorConfig.CollectProcessCmdline is
// set: command lines routinely carry tokens, passwords and connection
// strings passed as arguments (see CollectorConfig's own doc comment in
// collector.go), so it is opt-in rather than collected by default.
//
// Payload is a bare slice, not a struct wrapping one: SectionProcesses is
// registered Chunked in section.go, and telemetry.ChunkSection requires the
// value Collect returns to reflect as a slice directly (see chunk.go and the
// patches collector, which established this pattern first).
package processes

import (
	"context"
	"sort"
	"time"

	"github.com/shirou/gopsutil/v4/process"

	tel "sentinelgo/internal/telemetry"
)

// Name is the collector's identifier, also used as its section name.
const Name = tel.SectionProcesses

// Process describes one running process.
type Process struct {
	PID  int32  `json:"pid"`
	PPID int32  `json:"ppid,omitempty"`
	Name string `json:"name,omitempty"`
	Exe  string `json:"exe,omitempty"`
	// Username is the process owner. Empty when the platform denies reading
	// another user's process owner (common for a non-elevated caller — this
	// agent normally runs as SYSTEM/root, which does not hit that limit).
	Username string `json:"username,omitempty"`
	// CPUPercentAvg is a lifetime average (gopsutil's CPUPercent with no
	// sampling interval), not an instantaneous sample — named accordingly so
	// the semantics are honest rather than implying otherwise. Percent(1s)
	// per process would block a full second per process and is not used.
	CPUPercentAvg  float64 `json:"cpu_percent_avg"`
	MemoryRSSBytes uint64  `json:"memory_rss_bytes,omitempty"`
	CreateTime     string  `json:"create_time,omitempty"`
	// Cmdline is populated only when CollectorConfig.CollectProcessCmdline
	// is set — see the package doc.
	Cmdline string `json:"cmdline,omitempty"`
}

// Payload is the wire shape of the "processes" section — see the package doc
// for why this is a bare slice rather than a struct.
type Payload []Process

// Collector implements telemetry.Collector for process inventory.
type Collector struct{}

// New returns the Process Inventory collector.
func New() *Collector { return &Collector{} }

func (c *Collector) Name() string       { return Name }
func (c *Collector) Section() string    { return tel.SectionProcesses }
func (c *Collector) SchemaVersion() int { return 1 }

// Capability reports CapKeyProcesses as always supported: gopsutil's process
// enumeration works on every platform this agent targets.
//
// It deliberately does not report CapKeyProcessesCmdline here. A Collector
// reports exactly one capability key, and returning a non-supported state from
// this method makes runOne skip Collect entirely (see collector.go) — so
// signalling "command lines are off" through this return would suppress the
// whole process list along with them. The cmdline sub-key is reported through
// SubCapabilities instead.
func (c *Collector) Capability(context.Context, tel.CollectorConfig) (string, tel.CapabilityState) {
	return tel.CapKeyProcesses, tel.CapSupported
}

// SubCapabilities reports command-line capture separately from the process
// list, distinguishing "an administrator turned this off" from "this platform
// cannot provide it".
//
// The distinction is the whole point. Command-line capture is off by default
// for privacy (see the package doc), so disabled_by_config is the normal,
// expected state on every endpoint — and reporting it as unavailable_on_os, as
// this key did while unclaimed, told operators that Windows cannot read process
// command lines. It can; the agent was told not to.
//
// gopsutil reads command lines on every platform this agent targets, so when
// the flag is on the key is supported. Per-process denials are a partial read
// within a supported capability, not a capability failure, and are already
// reported as a collector warning.
func (c *Collector) SubCapabilities(_ context.Context, cfg tel.CollectorConfig) map[string]tel.CapabilityState {
	state := tel.CapDisabled
	if cfg.CollectProcessCmdline {
		state = tel.CapSupported
	}
	return map[string]tel.CapabilityState{tel.CapKeyProcessesCmdline: state}
}

// Collect gathers process inventory.
func (c *Collector) Collect(ctx context.Context, cfg tel.CollectorConfig) (any, tel.CollectorResult) {
	res, done := tel.NewResult(c.Name(), c.Section())

	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return Payload(nil), *done(err, "gopsutil:process", 0)
	}

	items := make([]Process, 0, len(procs))
	var readErrors int
	for _, p := range procs {
		item, ok := buildProcess(ctx, p, cfg.CollectProcessCmdline)
		if !ok {
			readErrors++
			continue
		}
		items = append(items, item)
	}
	if readErrors > 0 {
		res.AddWarning("some processes exited or were inaccessible during enumeration")
	}

	sortProcesses(items)
	if cfg.MaxItems > 0 && len(items) > cfg.MaxItems {
		items = items[:cfg.MaxItems]
	}

	return Payload(items), *done(nil, "gopsutil:process", len(items))
}

// buildProcess reads one process's fields. Only PID is required to succeed;
// every other field degrades to its zero value on error (the process exited
// mid-enumeration, or a field is unavailable for a system process) rather
// than discarding the whole entry — a process the agent can partially see is
// still worth reporting.
func buildProcess(ctx context.Context, p *process.Process, includeCmdline bool) (Process, bool) {
	item := Process{PID: p.Pid}

	if name, err := p.NameWithContext(ctx); err == nil {
		item.Name = name
	}
	if ppid, err := p.PpidWithContext(ctx); err == nil {
		item.PPID = ppid
	}
	if exe, err := p.ExeWithContext(ctx); err == nil {
		item.Exe = exe
	}
	if user, err := p.UsernameWithContext(ctx); err == nil {
		item.Username = user
	}
	if cpu, err := p.CPUPercentWithContext(ctx); err == nil {
		item.CPUPercentAvg = cpu
	}
	if mem, err := p.MemoryInfoWithContext(ctx); err == nil && mem != nil {
		item.MemoryRSSBytes = mem.RSS
	}
	if ct, err := p.CreateTimeWithContext(ctx); err == nil && ct > 0 {
		item.CreateTime = time.UnixMilli(ct).UTC().Format(time.RFC3339)
	}
	if includeCmdline {
		if cmdline, err := p.CmdlineWithContext(ctx); err == nil {
			item.Cmdline = cmdline
		}
	}

	// A process that exited between ProcessesWithContext's snapshot and this
	// read has an empty name AND exe AND zero create time — treat that
	// combination as "gone", not "a process with no name".
	if item.Name == "" && item.Exe == "" && item.CreateTime == "" {
		return item, false
	}
	return item, true
}

// sortProcesses orders the list deterministically by PID, so an unchanged
// process set hashes identically cycle to cycle — Fingerprint's documented
// requirement for any list payload.
func sortProcesses(p []Process) {
	sort.Slice(p, func(i, j int) bool { return p[i].PID < p[j].PID })
}
