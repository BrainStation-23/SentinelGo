// Package constants holds values shared across the agent.
package constants

import (
	"runtime"
	"slices"

	"sentinelgo/internal/binpath"
	"sentinelgo/internal/buildflavor"
)

// AgentCapabilities are the task features this binary supports, sent in the
// inventory payload so the backend never queues a task the agent can't run
// (contract v1 §6, #134). The backend matches each entry against
// ^[a-z0-9_]{1,64}$.
//
// Add an entry only in the same change that implements it: advertising a
// capability the binary lacks makes the backend send tasks that fail on
// the device. Advertise only what the server checks, and name that check
// next to the entry; an unchecked capability is dead contract (#563).
// Names are a contract: never reuse one in RetiredCapabilities.
var AgentCapabilities = []string{
	"script_inline_body_v1", // inline scripts[<os>].body (#135). Server: agent_has_capability before dispatching installer and App Catalog scripts
	"task_artifacts_v1",     // verified task artifacts (#136, #137). Server: installer-artifact dispatch, the console's custom install form
	"desktop_notify_v1",     // notify-user native task (#301). Server: native command → capability map
	"dlp_warn_v1",           // DLP action "warn" (#343). Server: agent_get_dlp_policy downgrades warn to monitor without it
	"packages_v1",           // package inventory and the sync-packages task (#421). Server: native command → capability map
	"yara_scan_v1",          // YARA ruleset sync, scans, match events (#404, #416). Server: agent_get_yara_ruleset sends a disabled bundle without it
	"yara_on_write_v1",      // scan files written into watched folders (#418). Server: bundle on_write only for agents with it
	"yara_scan_report_v1",   // scan progress and richer scan_summary (#497). Server: agent_enqueue_yara_events accepts scan_progress only with it
}

// RetiredCapabilities were advertised once and dropped because nothing on
// the server checks them (#563). Their names must never be reused, so an
// old agent that still sends one is never mistaken for a new feature.
var RetiredCapabilities = []string{
	"users_inventory_v2",   // #223
	"exposure_scope_v1",    // #251
	"local_admin_v1",       // #388
	"windows_mdm_state_v1", // #355
	"dlp_at_rest_v1",       // #331
	"apple_mdm_state_v1",   // #349
}

// CapabilityScriptPwsh means .ps1 scripts run under PowerShell 7 (pwsh) on
// macOS and Linux (#222). It depends on the device, so Capabilities adds it
// only when pwsh is installed. Windows runs .ps1 with Windows PowerShell and
// never reports it. Server: script rendering picks the pwsh slot with it.
const CapabilityScriptPwsh = "script_pwsh_v1" // #nosec G101 - a capability name, not a credential

// CapabilityMDMEnroll means the agent runs the mdm-enroll native task: on
// macOS ADE re-enrollment or a profile presented to the console user (#350),
// on Windows silent enrollment (#356). Server: native command → capability
// map.
const CapabilityMDMEnroll = "mdm_enroll_v1"

// CapabilityMDMSync means the agent runs the mdm-sync native task: start an
// MDM session now, standing in for push (#357). Server: native command →
// capability map, and the Windows MDM sync answers "unsupported" without it.
const CapabilityMDMSync = "mdm_sync_v1"

// CapabilityMDMUnenroll means the agent runs the mdm-unenroll native task:
// remove this deployment's MDM enrollment (#356). Server: native command →
// capability map.
const CapabilityMDMUnenroll = "mdm_unenroll_v1"

// CapabilityAdminPasswordRotation means the agent rotates a local admin
// account's password and escrows it before setting it: the
// agent_*_admin_password RPCs and the admin-password-rotate task (#361).
// Windows only. Server: rotation is scheduled only for agents with it.
const CapabilityAdminPasswordRotation = "admin_password_rotation_v1" // #nosec G101 - a capability name, not a credential

// CapabilityDLPNetworkControl means the agent applies the file DLP bundle's
// modules.files.network_control: blocked apps and taint blocks through WFP
// (#427, Compliance-OS#910). Windows only. Server: the policy bundle
// carries network_control only for agents with it.
const CapabilityDLPNetworkControl = "dlp_network_control_v1"

// goos is runtime.GOOS; a var so tests can check other platforms' lists.
var goos = runtime.GOOS

// pwshInstalled reports whether the task executor can find pwsh. It uses the
// same strict lookup as the executor, so the capability is never advertised
// for a pwsh the executor would not run. A var so tests can stub it.
var pwshInstalled = func() bool {
	if goos == "windows" {
		return false
	}
	_, ok := binpath.Lookup("pwsh")
	return ok
}

// Capabilities returns AgentCapabilities plus the capabilities this device
// supports right now. It's checked on every call (each inventory report), so
// installing PowerShell later is picked up without a restart. The result is a
// fresh slice, so callers can't change what the agent advertises.
func Capabilities() []string {
	caps := deviceCapabilities()
	if buildflavor.ReadOnly {
		caps = withoutReadOnlyLacks(caps)
	}
	return caps
}

// withoutReadOnlyLacks drops ReadOnlyLacks from caps.
func withoutReadOnlyLacks(caps []string) []string {
	return slices.DeleteFunc(caps, func(c string) bool { return slices.Contains(ReadOnlyLacks, c) })
}

// ReadOnlyLacks are the capabilities the read-only build doesn't have
// (#547): its gated features are compiled out, so it never advertises them.
var ReadOnlyLacks = []string{
	"script_inline_body_v1", "task_artifacts_v1", CapabilityScriptPwsh, // Scripts
	CapabilityAdminPasswordRotation, CapabilityMDMSync, CapabilityMDMUnenroll, // DeviceActions
	"dlp_warn_v1", CapabilityDLPNetworkControl, // DLPEnforcement
	"yara_scan_v1", "yara_on_write_v1", "yara_scan_report_v1", // YARA
	"desktop_notify_v1", // NotifyUser
	CapabilityMDMEnroll, // MDMEnroll
}

// deviceCapabilities is every capability of the full build on this device.
func deviceCapabilities() []string {
	caps := append([]string{}, AgentCapabilities...)
	if pwshInstalled() {
		caps = append(caps, CapabilityScriptPwsh)
	}
	switch goos {
	case "darwin":
		caps = append(caps, CapabilityMDMEnroll)
	case "windows":
		caps = append(caps, CapabilityMDMSync, CapabilityMDMEnroll, CapabilityMDMUnenroll, CapabilityAdminPasswordRotation,
			CapabilityDLPNetworkControl)
	}
	return caps
}
