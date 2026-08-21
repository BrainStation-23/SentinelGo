// Package health implements the telemetry Health collector, filling the
// "health" section: CPU/memory/disk utilisation, uptime, and battery detail
// — the exact grouping docs/telemetry/04-architecture.md's class table
// assigns to ClassHealth ("CPU/memory/disk utilisation, battery, uptime").
//
// This section is never fingerprinted or reconciled (see Class.Fingerprinted
// in class.go): a resource sample changes on every read by definition, so
// hashing it would mark it permanently changed and defeat reconciliation —
// ShouldUpload short-circuits ClassHealth to always send instead.
//
// CPU/memory/disk/uptime go through gopsutil — pure Go, no per-OS files
// needed, the same reasoning the matrix doc gives for process inventory.
// Battery detail is genuinely platform-specific (native WMI on Windows,
// sysfs on Linux, ioreg on macOS) and has its own per-platform files.
package health

import (
	"context"
	"errors"
	"fmt"
	"runtime"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"

	tel "sentinelgo/internal/telemetry"
)

// errAllCoreMetricsFailed drives Collect's Status to StatusError (via
// SanitizeError's ReasonUnexpected fallback) when every one of
// CPU/memory/disk/uptime failed to read this cycle — gopsutil itself is
// broken or blocked, not a single metric being transiently unavailable.
var errAllCoreMetricsFailed = errors.New("health: all core metrics failed to read")

// Name is the collector's identifier, also used as its section name.
const Name = tel.SectionHealth

// Battery describes battery detail. Every numeric field is a pointer: nil
// means this platform's mechanism did not report that specific value —
// docs/telemetry/03-collection-matrix.md notes Win32_Battery.DesignCapacity
// is "almost always NULL", so a real device very often has some but not all
// of these — never a guessed zero.
type Battery struct {
	Present               bool     `json:"present"`
	PercentRemaining      *float64 `json:"percent_remaining,omitempty"`
	Charging              *bool    `json:"charging,omitempty"`
	DesignCapacityMWh     *uint64  `json:"design_capacity_mwh,omitempty"`
	FullChargeCapacityMWh *uint64  `json:"full_charge_capacity_mwh,omitempty"`
	CycleCount            *int     `json:"cycle_count,omitempty"`
}

// Payload is the wire shape of the "health" section.
type Payload struct {
	CPUPercent    float64  `json:"cpu_percent"`
	MemoryPercent float64  `json:"memory_percent"`
	DiskPercent   float64  `json:"disk_percent,omitempty"`
	UptimeSeconds uint64   `json:"uptime_seconds"`
	Battery       *Battery `json:"battery,omitempty"`
}

// Collector implements telemetry.Collector for resource and battery health.
type Collector struct{}

// New returns the Health collector.
func New() *Collector { return &Collector{} }

func (c *Collector) Name() string       { return Name }
func (c *Collector) Section() string    { return tel.SectionHealth }
func (c *Collector) SchemaVersion() int { return 1 }

// Capability reports CapKeyBatteryDetail based on whether this host has a
// battery at all — CapNotPresent on a desktop is the correct, permanent
// answer, not a fault to keep retrying. CPU/memory/disk/uptime have no
// capability gate: every host has them.
//
// This does the same battery lookup Collect will do; the duplication is
// deliberate rather than cached, matching the identity/virtualization/
// directory collectors' precedent — a capability check must reflect current
// state on every call, including if a laptop's battery is later removed.
func (c *Collector) Capability(ctx context.Context, _ tel.CollectorConfig) (string, tel.CapabilityState) {
	battery, _, _ := platformBattery(ctx)
	if battery != nil && battery.Present {
		return tel.CapKeyBatteryDetail, tel.CapSupported
	}
	return tel.CapKeyBatteryDetail, tel.CapNotPresent
}

// Collect gathers one resource/health sample.
func (c *Collector) Collect(ctx context.Context, _ tel.CollectorConfig) (any, tel.CollectorResult) {
	res, done := tel.NewResult(c.Name(), c.Section())

	payload := Payload{}
	var warnings []string
	var coreFailures int

	if pct, err := cpu.PercentWithContext(ctx, 0, false); err == nil && len(pct) > 0 {
		payload.CPUPercent = pct[0]
	} else {
		warnings = append(warnings, "cpu percent read failed")
		coreFailures++
	}

	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		payload.MemoryPercent = vm.UsedPercent
	} else {
		warnings = append(warnings, "memory read failed")
		coreFailures++
	}

	if usage, err := disk.UsageWithContext(ctx, systemVolumePath()); err == nil {
		payload.DiskPercent = usage.UsedPercent
	} else {
		warnings = append(warnings, "disk usage read failed")
		coreFailures++
	}

	if info, err := host.InfoWithContext(ctx); err == nil {
		payload.UptimeSeconds = info.Uptime
	} else {
		warnings = append(warnings, "uptime read failed")
		coreFailures++
	}

	battery, batWarnings, batSource := platformBattery(ctx)
	payload.Battery = battery
	warnings = append(warnings, batWarnings...)

	for _, w := range warnings {
		res.AddWarning(w)
	}

	source := "gopsutil"
	if batSource != "" {
		source += ", " + batSource
	}

	// A core metric reading 0 on failure (CPUPercent, MemoryPercent) is
	// indistinguishable on the wire from a genuine 0% reading — there is no
	// pointer-typed "unknown" here the way DomainJoined or PendingReboot use
	// elsewhere in this codebase, since a resource-utilisation sample is
	// expected to legitimately be exactly 0 sometimes. Reporting Status
	// honestly is what keeps that ambiguity from becoming silent: a real
	// backend consumer must treat a Partial/Error health sample as
	// untrustworthy regardless of what the numbers say, the same way a
	// collector-health dashboard already distinguishes "reported healthy"
	// from "collector failing" for every other section.
	var err error
	switch {
	case coreFailures == 4:
		err = errAllCoreMetricsFailed
	case coreFailures > 0:
		// Reuses the existing ErrEmptyOutput sentinel rather than adding a
		// new one: its documented mapping (StatusPartial, "some data was
		// produced, but a sub-query failed") is exactly this situation.
		err = fmt.Errorf("health: %w", tel.ErrEmptyOutput)
	}

	return payload, *done(err, source, 1)
}

// systemVolumePath is the volume disk usage is measured against: the root
// filesystem on Unix, the system drive on Windows.
func systemVolumePath() string {
	if runtime.GOOS == "windows" {
		return `C:\`
	}
	return "/"
}
