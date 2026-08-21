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
package collectors

import (
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
		secureboot.New(),
		tpm.New(),
	} {
		if err := set.Register(c); err != nil {
			return err
		}
	}
	return nil
}
