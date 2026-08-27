// Package collectors is the single place production code registers telemetry
// collectors, so main_integration.go (the live agent) and cmd/sentinelgo/cli
// (the -capabilities/-telemetry-cycle/-telemetry-health debug commands) can
// never drift out of sync on which collectors are wired in.
//
// Phase C1 registered Device Identity, VM/Hypervisor Detection and
// AD/Entra/Domain Join. Phase C2 added Sessions. Phase C3 added OS
// Completeness. Phase C4 added Physical Disks and Volumes. Phase C5 added
// lightweight Network, completing Phase C's P0 scope. Phase D1 added
// per-volume Encryption Detail. Phase D2 added Patch Inventory. Phase D3
// added Security Posture (password policy, privileged accounts). Phase E1
// adds Process Inventory. Later phases add to RegisterAll rather than
// duplicating registration at each call site.
//
// Secure Boot, TPM and Endpoint Protection were added last: the first two
// sections were registered from the start but had no collector, so their
// capability keys reported the manifest default (a claim that the OS could not
// provide the data) on machines that plainly could. Endpoint Protection is what
// makes the firewall/real-time/tamper change events possible at all.
//
// The routing-table collector was added afterwards to give the long-unowned
// CapKeyNetworkRoutingTable capability key a real owner and to make the
// collect_routing_table config flag mean something. It is opt-in and reports
// CapDisabled when off, so registering it changes nothing by default.
//
// The bridge collectors (firmware, cpu, memory_modules) were the last addition.
// Those three sections were declared in section.go from the start with no owner,
// so the section-merge path had no authoritative source for a device's BIOS
// version, CPU identity or DIMM layout even though the legacy inventory had been
// collecting all of it. They reuse the existing osinfo collectors read-only
// rather than duplicating hardware reads across three platforms.
package collectors

import (
	"sentinelgo/internal/telemetry/collectors/bridge"
	"sentinelgo/internal/telemetry/collectors/certificates"
	"sentinelgo/internal/telemetry/collectors/directory"
	"sentinelgo/internal/telemetry/collectors/encryption"
	"sentinelgo/internal/telemetry/collectors/health"
	"sentinelgo/internal/telemetry/collectors/identity"
	"sentinelgo/internal/telemetry/collectors/network"
	"sentinelgo/internal/telemetry/collectors/osdetail"
	"sentinelgo/internal/telemetry/collectors/patches"
	"sentinelgo/internal/telemetry/collectors/persistence"
	"sentinelgo/internal/telemetry/collectors/physicaldisks"
	"sentinelgo/internal/telemetry/collectors/posture"
	"sentinelgo/internal/telemetry/collectors/processes"
	"sentinelgo/internal/telemetry/collectors/protection"
	"sentinelgo/internal/telemetry/collectors/routes"
	"sentinelgo/internal/telemetry/collectors/secureboot"
	"sentinelgo/internal/telemetry/collectors/sessions"
	"sentinelgo/internal/telemetry/collectors/tpm"
	"sentinelgo/internal/telemetry/collectors/virtualization"
	"sentinelgo/internal/telemetry/collectors/volumes"

	tel "sentinelgo/internal/telemetry"
)

// RegisterAll registers every collector this build ships against set.
//
// Register only fails on a duplicate or malformed name, which would be a
// programming error in this file, not a runtime condition — callers should
// treat a non-nil error as fatal to startup, the same way a bad task
// registration is.
func RegisterAll(set *tel.CollectorSet) error {
	// The bridge collectors come first so the sections they own are visibly
	// grouped: they reuse the legacy inventory collectors read-only rather than
	// adding a second hardware implementation. See the bridge package doc.
	for _, c := range bridge.New() {
		if err := set.Register(c); err != nil {
			return err
		}
	}

	for _, c := range []tel.Collector{
		certificates.New(),
		health.New(),
		identity.New(),
		virtualization.New(),
		directory.New(),
		sessions.New(),
		osdetail.New(),
		physicaldisks.New(),
		volumes.New(),
		network.New(),
		encryption.New(),
		patches.New(),
		persistence.New(),
		posture.New(),
		processes.New(),
		protection.New(),
		routes.New(),
		secureboot.New(),
		tpm.New(),
	} {
		if err := set.Register(c); err != nil {
			return err
		}
	}
	return nil
}
