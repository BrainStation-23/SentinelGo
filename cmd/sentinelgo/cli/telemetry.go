package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	tel "sentinelgo/internal/telemetry"
	"sentinelgo/internal/telemetry/collectors"

	"sentinelgo/internal/config"
	"sentinelgo/internal/sanitize"
	telemetrysvc "sentinelgo/internal/service/telemetry"
)

// telemetryCycleTimeout bounds a manually-triggered collection cycle.
const telemetryCycleTimeout = 2 * time.Minute

// openTelemetry opens the telemetry service for a CLI command.
//
// The stores are created on demand, so these commands work even when the
// telemetry task has never run. A disabled layer is reported rather than
// treated as an error: "off" is a valid state to inspect.
func openTelemetry(cfg *config.Config) (*telemetrysvc.Service, bool) {
	if !cfg.TelemetryEnabled {
		fmt.Println("Note: telemetry is disabled (telemetry_enabled=false).")
		fmt.Println("      Local state is still readable; the scheduled task does not run.")
		fmt.Println()
	}

	set := tel.NewCollectorSet()
	if err := collectors.RegisterAll(set); err != nil {
		log.Printf("Error: could not register telemetry collectors: %v", err)
		return nil, false
	}

	svc, err := telemetrysvc.New(cfg, set)
	if err != nil {
		log.Printf("Error: could not open telemetry stores: %v", err)
		return nil, false
	}
	return svc, true
}

// HandleTelemetryHealth prints per-domain collection health and queue state.
func HandleTelemetryHealth(cfg *config.Config) {
	svc, ok := openTelemetry(cfg)
	if !ok {
		return
	}
	defer func() { _ = svc.Close() }()

	health := svc.Health()
	depth, _ := svc.QueueDepth()
	bytes, _ := svc.QueueBytes()
	dead, _ := svc.DeadLetterDepth()

	fmt.Println("=== Telemetry Health ===")
	fmt.Printf("Enabled:            %v\n", cfg.TelemetryEnabled)
	fmt.Printf("Collect interval:   %v\n", cfg.GetTelemetryCollectInterval())
	fmt.Printf("Queue depth:        %d message(s)\n", depth)
	fmt.Printf("Queue size:         %d bytes (cap %d)\n", bytes, cfg.GetTelemetryQueueMaxBytes())
	fmt.Printf("Dead-lettered:      %d message(s)\n", dead)
	fmt.Printf("Dropped (evicted):  %d\n", health.DroppedEventCount)
	fmt.Printf("Collector failures: %d\n", health.CollectorFailures)
	fmt.Println()

	if dead > 0 {
		fmt.Printf("WARNING: %d message(s) exhausted their delivery attempts and were\n", dead)
		fmt.Println("         moved out of the delivery path. They are retained locally")
		fmt.Println("         for inspection and are NOT counted in queue depth. This")
		fmt.Println("         usually means the backend is rejecting the payload shape.")
		fmt.Println()
	}

	if len(health.Domains) == 0 {
		fmt.Println("No domains have reported yet.")
		fmt.Println("This is expected before the first collection cycle, or while no")
		fmt.Println("collectors are registered.")
		return
	}

	fmt.Println("Domains:")
	for _, d := range health.Domains {
		fmt.Printf("  %-20s %s\n", sanitize.ForLog(d.Domain)+":", sanitize.ForLog(d.State))
		if d.LastSuccessfulCollect != "" {
			fmt.Printf("  %-20s last collected %s\n", "", sanitize.ForLog(d.LastSuccessfulCollect))
		}
		if d.LastUpload != "" {
			fmt.Printf("  %-20s last uploaded  %s\n", "", sanitize.ForLog(d.LastUpload))
		}
		if d.ConsecutiveFailures > 0 {
			fmt.Printf("  %-20s %d consecutive failure(s), last: %s\n",
				"", d.ConsecutiveFailures, sanitize.ForLog(d.LastError))
		}
	}
}

// HandleCapabilities prints what this endpoint can and cannot report.
func HandleCapabilities(cfg *config.Config) {
	svc, ok := openTelemetry(cfg)
	if !ok {
		return
	}
	defer func() { _ = svc.Close() }()

	set := svc.Domain().Collectors()
	caps := tel.NewCapabilityManifest()

	collectorCfg := tel.CollectorConfigFrom(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, c := range set.All() {
		key, state := c.Capability(ctx, collectorCfg)
		if key != "" {
			caps.Set(key, state)
		}
	}

	fmt.Println("=== Telemetry Capabilities ===")
	fmt.Println()
	fmt.Println("  supported          present and collected")
	fmt.Println("  not_present        hardware or feature genuinely absent from this device")
	fmt.Println("  unsupported        present, but this driver/firmware/config will not expose it")
	fmt.Println("  disabled           switched off by configuration")
	fmt.Println("  unavailable_on_os  this operating system cannot provide it")
	fmt.Println()

	byState := make(map[tel.CapabilityState][]string)
	for _, key := range caps.Keys() {
		state := caps.Get(key)
		byState[state] = append(byState[state], key)
	}

	order := []tel.CapabilityState{
		tel.CapSupported, tel.CapNotPresent, tel.CapUnsupported,
		tel.CapDisabled, tel.CapUnavailableOS,
	}
	for _, state := range order {
		keys := byState[state]
		if len(keys) == 0 {
			continue
		}
		sort.Strings(keys)
		fmt.Printf("%s (%d):\n", state, len(keys))
		for _, k := range keys {
			fmt.Printf("  %s\n", sanitize.ForLog(k))
		}
		fmt.Println()
	}

	if set.Len() == 0 {
		fmt.Println("No collectors are registered yet, so every capability reports its")
		fmt.Println("default state. Values become meaningful once collectors ship.")
	}
}

// HandleTelemetryCycle runs one collection cycle and prints what it decided.
//
// It deliberately does NOT upload. Collection and delivery are separate steps,
// and a debug command should let an operator inspect what would be sent before
// anything leaves the device; the scheduled task performs the flush.
func HandleTelemetryCycle(cfg *config.Config) {
	svc, ok := openTelemetry(cfg)
	if !ok {
		return
	}
	defer func() { _ = svc.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), telemetryCycleTimeout)
	defer cancel()

	start := time.Now()
	report, err := svc.RunCycle(ctx)
	if err != nil {
		log.Printf("Telemetry cycle failed: %v", err)
		return
	}

	fmt.Println("=== Telemetry Cycle ===")
	fmt.Printf("Duration:  %v\n", time.Since(start).Round(time.Millisecond))
	fmt.Printf("Collected: %d section(s)\n", len(report.CollectedSections))
	fmt.Printf("Queued:    %d section(s) in %d message(s)\n",
		len(report.UploadedSections), report.Messages)
	fmt.Printf("Skipped:   %d section(s)\n", len(report.SkippedSections))
	if report.Evicted > 0 {
		fmt.Printf("Evicted:   %d message(s) to stay within queue bounds\n", report.Evicted)
	}
	if len(report.Truncated) > 0 {
		fmt.Printf("TRUNCATED: %s (an item exceeded the size limit and could not be sent)\n",
			sanitize.ForLog(strings.Join(report.Truncated, ", ")))
	}
	fmt.Println()

	if len(report.Reasons) > 0 {
		fmt.Println("Per-section decisions:")
		names := make([]string, 0, len(report.Reasons))
		for name := range report.Reasons {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Printf("  %-20s %s\n", sanitize.ForLog(name)+":", sanitize.ForLog(report.Reasons[name]))
		}
		fmt.Println()
	}

	if len(report.Results) > 0 {
		fmt.Println("Collector results:")
		for _, r := range report.Results {
			line := fmt.Sprintf("  %-20s %-18s %5dms", sanitize.ForLog(r.Collector)+":",
				sanitize.ForLog(string(r.Status)), r.DurationMS)
			if r.Source != "" {
				line += "  via " + sanitize.ForLog(r.Source)
			}
			if r.Error != "" {
				line += "  (" + sanitize.ForLog(r.Error) + ")"
			}
			fmt.Println(line)
		}
		fmt.Println()
	}

	depth, _ := svc.QueueDepth()
	fmt.Printf("Queue now holds %d message(s); delivery happens on the scheduled task.\n", depth)

	if len(report.CollectedSections) == 0 {
		fmt.Println()
		fmt.Println("No sections were collected. This is expected while no collectors")
		fmt.Println("are registered.")
	}
}

// HandleTelemetryReset clears local telemetry state so the next cycle resends
// everything.
//
// Scope is deliberately narrow and is stated explicitly to the operator: only
// the two telemetry databases are touched. Device registration, credentials,
// agent identity, the software and services catalogs, the audit-log queue and
// the task store are all left intact.
func HandleTelemetryReset(cfg *config.Config) {
	svc, ok := openTelemetry(cfg)
	if !ok {
		return
	}
	defer func() { _ = svc.Close() }()

	depthBefore, _ := svc.QueueDepth()

	if err := svc.ResetState(); err != nil {
		log.Printf("Telemetry reset failed: %v", err)
		return
	}

	fmt.Println("=== Telemetry Reset ===")
	fmt.Println("Cleared:")
	fmt.Println("  - telemetry section state (hashes and reconcile timestamps)")
	fmt.Printf("  - outbound telemetry queue (%d undelivered message(s) discarded)\n", depthBefore)
	fmt.Println()
	fmt.Println("Left untouched:")
	fmt.Println("  - device registration and agent identity")
	fmt.Println("  - credentials (agent secret, access and refresh tokens)")
	fmt.Println("  - software and services catalogs")
	fmt.Println("  - audit-log queue and task store")
	fmt.Println()
	fmt.Println("The next telemetry cycle will treat every section as a first upload.")
}

// HandleTelemetryHealthJSON prints the health report as JSON, for scripting.
func HandleTelemetryHealthJSON(cfg *config.Config) {
	svc, ok := openTelemetry(cfg)
	if !ok {
		return
	}
	defer func() { _ = svc.Close() }()

	data, err := json.MarshalIndent(svc.Health(), "", "  ")
	if err != nil {
		log.Printf("Error marshaling telemetry health: %v", err)
		return
	}
	fmt.Println(string(data))
}
