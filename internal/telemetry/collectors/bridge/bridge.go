// Package bridge fills the telemetry sections whose data the legacy inventory
// already collects correctly: firmware, cpu and memory_modules.
//
// # Why a bridge and not three new collectors
//
// These three sections were declared in section.go from the start and never
// given an owner, so the section-merge path had no authoritative source for
// them: an operator querying the telemetry tables for a device's BIOS version
// or DIMM layout found nothing, even though the agent had been collecting all
// of it on the legacy inventory cycle the whole time.
//
// The obvious fix — write telemetry collectors that query WMI, sysfs and
// system_profiler for firmware, CPU and memory — is the wrong one. It would
// produce two independent implementations of the same hardware reads on three
// platforms, which then disagree: two code paths, two sets of platform quirks,
// two places to fix a parsing bug, and a support question ("why does the
// telemetry section say 16 GB when the inventory says 32 GB?") with no good
// answer. Hardware facts should have exactly one implementation.
//
// So these collectors call the existing osinfo packages read-only and reshape
// what comes back. There is one implementation of "how do I read this
// machine's DIMMs"; this package decides how it appears in a telemetry section.
//
// # What this costs
//
// One extra invocation of three cheap osinfo collectors per telemetry cycle,
// and only when the section is due: all three are registered at a 6-hour
// collect interval in section.go, being static hardware. None of them shells
// out on the hot path the way the security collector does.
//
// # What this deliberately does not bridge
//
// Only sections that are declared and unowned. Sections with a real telemetry
// collector — identity, physical_disks, network and the rest — keep theirs;
// bridging those would recreate the duplicate-implementation problem from the
// other direction.
package bridge

import (
	"context"
	"sort"

	cpupkg "sentinelgo/internal/osinfo/cpu"
	rampkg "sentinelgo/internal/osinfo/ram"
	systempkg "sentinelgo/internal/osinfo/system"
	tel "sentinelgo/internal/telemetry"
)

// New returns every bridge collector.
//
// A constructor per section would work, but returning them together keeps the
// registration site honest about what this package is: one bridge over three
// sections, not three unrelated collectors that happen to share a directory.
func New() []tel.Collector {
	return []tel.Collector{
		&FirmwareCollector{},
		&CPUCollector{},
		&MemoryModulesCollector{},
	}
}

// ── firmware ─────────────────────────────────────────────────────────────────

// FirmwarePayload is the wire shape of the "firmware" section.
type FirmwarePayload struct {
	// Type is the boot mode as the platform reports it: "UEFI", "BIOS", or
	// empty where this host does not say. Two of the three platforms hardcode
	// it (gap analysis item 7); the bridge reports what osinfo returns rather
	// than improving on it here, because improving it belongs in osinfo where
	// the legacy inventory benefits too.
	Type string `json:"type,omitempty"`
	// Vendor is the firmware vendor, e.g. "American Megatrends Inc.".
	Vendor string `json:"vendor,omitempty"`
	// Version is the firmware/BIOS version string.
	Version string `json:"version,omitempty"`
}

// FirmwareCollector bridges osinfo/system's firmware read.
type FirmwareCollector struct{}

func (c *FirmwareCollector) Name() string       { return tel.SectionFirmware }
func (c *FirmwareCollector) Section() string    { return tel.SectionFirmware }
func (c *FirmwareCollector) SchemaVersion() int { return 1 }

// Capability claims no capability key. Firmware has none in the manifest, and
// inventing one would add a key to the backend contract for a section that has
// never needed to explain its own absence.
func (c *FirmwareCollector) Capability(context.Context, tel.CollectorConfig) (string, tel.CapabilityState) {
	return "", tel.CapSupported
}

func (c *FirmwareCollector) Collect(ctx context.Context, _ tel.CollectorConfig) (any, tel.CollectorResult) {
	res, done := tel.NewResult(c.Name(), c.Section())

	if err := ctx.Err(); err != nil {
		return FirmwarePayload{}, *done(err, sourceLegacyInventory, 0)
	}

	fType, vendor, version := systempkg.GetFirmwareInfo()
	payload := FirmwarePayload{Type: fType, Vendor: vendor, Version: version}

	// An all-empty result is reported as unsupported rather than success: the
	// section would otherwise arrive as an empty object indistinguishable from
	// a machine whose firmware genuinely exposes nothing.
	if fType == "" && vendor == "" && version == "" {
		res.AddWarning("no firmware fields available from the platform")
		r := *done(nil, sourceLegacyInventory, 0)
		r.Status = tel.StatusUnsupported
		return payload, r
	}

	return payload, *done(nil, sourceLegacyInventory, 1)
}

// ── cpu ──────────────────────────────────────────────────────────────────────

// CPUPayload is the wire shape of the "cpu" section.
//
// Usage is deliberately absent even though osinfo collects it. It is a
// point-in-time sample that changes on every read, and this section is
// fingerprinted at a 6-hour collect interval — including it would make a
// machine whose CPU has not changed re-upload the section every cycle forever.
// Live CPU load is already carried by the health section, which is
// ClassHealth and therefore never fingerprinted.
type CPUPayload struct {
	ModelName          string `json:"model_name,omitempty"`
	Manufacturer       string `json:"manufacturer,omitempty"`
	Architecture       string `json:"architecture,omitempty"`
	ClockSpeed         string `json:"clock_speed,omitempty"`
	Cores              int    `json:"cores,omitempty"`
	LogicalCores       int    `json:"logical_cores,omitempty"`
	NumberCoresDetail  int    `json:"number_cores_detail,omitempty"`
	ProcessorSignature string `json:"processor_signature,omitempty"`
}

// CPUCollector bridges osinfo/cpu.
type CPUCollector struct{}

func (c *CPUCollector) Name() string       { return tel.SectionCPU }
func (c *CPUCollector) Section() string    { return tel.SectionCPU }
func (c *CPUCollector) SchemaVersion() int { return 1 }

// Capability claims no capability key: every platform can identify its own CPU.
func (c *CPUCollector) Capability(context.Context, tel.CollectorConfig) (string, tel.CapabilityState) {
	return "", tel.CapSupported
}

func (c *CPUCollector) Collect(ctx context.Context, _ tel.CollectorConfig) (any, tel.CollectorResult) {
	res, done := tel.NewResult(c.Name(), c.Section())

	if err := ctx.Err(); err != nil {
		return CPUPayload{}, *done(err, sourceLegacyInventory, 0)
	}

	result := cpupkg.Get()
	payload := CPUPayload{
		ModelName:          result.Info.ModelName,
		Manufacturer:       result.Detailed.Manufacturer,
		Architecture:       result.Detailed.ArchitectureType,
		ClockSpeed:         result.Detailed.ClockSpeed,
		Cores:              result.Info.Cores,
		LogicalCores:       result.Detailed.NumberLogicalCores,
		NumberCoresDetail:  result.Detailed.NumberCores,
		ProcessorSignature: result.Detailed.Processor,
	}

	if payload.ModelName == "" && payload.ProcessorSignature == "" {
		res.AddWarning("no CPU identity available from the platform")
		r := *done(nil, sourceLegacyInventory, 0)
		r.Status = tel.StatusUnsupported
		return payload, r
	}

	return payload, *done(nil, sourceLegacyInventory, 1)
}

// ── memory modules ───────────────────────────────────────────────────────────

// MemoryModule is one physical DIMM.
type MemoryModule struct {
	Name          string `json:"name,omitempty"`
	Slot          string `json:"slot,omitempty"`
	CapacityBytes uint64 `json:"capacity_bytes,omitempty"`
	Manufacturer  string `json:"manufacturer,omitempty"`
	MemoryType    string `json:"memory_type,omitempty"`
	FormFactor    string `json:"form_factor,omitempty"`
	ClockSpeedMHz int    `json:"clock_speed_mhz,omitempty"`
	// Serial is the module serial number where the platform exposes it. It is
	// hardware identity, not user data, and is what makes a specific failing
	// DIMM identifiable across an RMA.
	Serial string `json:"serial,omitempty"`
}

// MemoryModulesPayload is the wire shape of the "memory_modules" section.
//
// Installed capacity only. Used/free memory is a live measurement and belongs
// to the health section for the same reason CPU usage does.
type MemoryModulesPayload struct {
	TotalCapacityBytes uint64         `json:"total_capacity_bytes,omitempty"`
	Modules            []MemoryModule `json:"modules"`
}

// MemoryModulesCollector bridges osinfo/ram.
type MemoryModulesCollector struct{}

func (c *MemoryModulesCollector) Name() string       { return tel.SectionMemoryModules }
func (c *MemoryModulesCollector) Section() string    { return tel.SectionMemoryModules }
func (c *MemoryModulesCollector) SchemaVersion() int { return 1 }

// Capability claims no capability key. Per-module detail is genuinely
// unavailable on some hosts (a VM has no DIMMs to describe), which is reported
// through the collector status rather than a manifest key that nothing else
// consults.
func (c *MemoryModulesCollector) Capability(context.Context, tel.CollectorConfig) (string, tel.CapabilityState) {
	return "", tel.CapSupported
}

func (c *MemoryModulesCollector) Collect(ctx context.Context, cfg tel.CollectorConfig) (any, tel.CollectorResult) {
	res, done := tel.NewResult(c.Name(), c.Section())

	if err := ctx.Err(); err != nil {
		return MemoryModulesPayload{}, *done(err, sourceLegacyInventory, 0)
	}

	info := rampkg.Get()
	modules := make([]MemoryModule, 0, len(info.RAMs))
	for _, stick := range info.RAMs {
		modules = append(modules, MemoryModule{
			Name:          stick.Name,
			Slot:          stick.Slot,
			CapacityBytes: stick.Capacity,
			Manufacturer:  stick.Manufacturer,
			MemoryType:    stick.ArchitectureType,
			FormFactor:    stick.FormFactor,
			ClockSpeedMHz: stick.ClockSpeedMHz,
			Serial:        stick.Serial,
		})
	}
	SortModules(modules)

	if cfg.MaxItems > 0 && len(modules) > cfg.MaxItems {
		res.AddWarning("memory module list truncated to the configured item limit")
		modules = modules[:cfg.MaxItems]
	}

	payload := MemoryModulesPayload{
		TotalCapacityBytes: info.TotalCapacity,
		Modules:            modules,
	}

	// A virtual machine reports total memory but no physical modules. That is
	// the hardware genuinely not being there, not a collection failure, so it
	// must not count against telemetry health.
	if len(modules) == 0 {
		res.AddWarning("no per-module memory detail available on this host")
		r := *done(nil, sourceLegacyInventory, 0)
		r.Status = tel.StatusUnsupported
		return payload, r
	}

	return payload, *done(nil, sourceLegacyInventory, len(modules))
}

// sourceLegacyInventory names the mechanism in CollectorResult.Source.
//
// It says "reused from the legacy inventory collector" rather than naming WMI
// or sysfs, because that is the honest answer to "where did this come from" and
// it is what makes the bridge visible server-side. If one of these sections
// ever gains a collector of its own, the Source value changes and the switch is
// apparent in the data instead of being silent.
const sourceLegacyInventory = "osinfo:legacy-inventory"

// SortModules orders modules deterministically.
//
// Required, not cosmetic: these sections are fingerprinted, and WMI and
// system_profiler do not guarantee a stable enumeration order between reads. An
// unchanged set of DIMMs listed in a different order would hash differently and
// re-upload every cycle.
func SortModules(modules []MemoryModule) {
	sort.Slice(modules, func(i, j int) bool {
		a, b := modules[i], modules[j]
		if a.Slot != b.Slot {
			return a.Slot < b.Slot
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Serial != b.Serial {
			return a.Serial < b.Serial
		}
		return a.CapacityBytes < b.CapacityBytes
	})
}
