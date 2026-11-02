// Package constants holds values shared across the agent.
package constants

import (
	"runtime"

	"sentinelgo/internal/binpath"
)

// AgentCapabilities are the task features this binary supports, sent in the
// inventory payload so the backend never queues a task the agent can't run
// (contract v1 §6, #134). The backend matches each entry against
// ^[a-z0-9_]{1,64}$.
//
// Add an entry only in the same change that implements it: advertising a
// capability the binary lacks makes the backend send tasks that fail on
// the device.
var AgentCapabilities = []string{
	"script_inline_body_v1", // inline scripts[<os>].body (#135)
	"task_artifacts_v1",     // verified task artifacts (#136, #137)
	"users_inventory_v2",    // built-in accounts, local_admin_members, signed_in_users, … (#223)
	"exposure_scope_v1",     // risky_services[].remote_scope, remote_addresses, on_public_address (#251)
	"desktop_notify_v1",     // notify-user native task: an admin's desktop notification (#301)
	"dlp_warn_v1",           // DLP policy action "warn": keep the content, notify the user (#343)
}

// CapabilityScriptPwsh means .ps1 scripts run under PowerShell 7 (pwsh) on
// macOS and Linux (#222). It depends on the device, so Capabilities adds it
// only when pwsh is installed. Windows runs .ps1 with Windows PowerShell and
// never reports it.
const CapabilityScriptPwsh = "script_pwsh_v1" // #nosec G101 - a capability name, not a credential

// CapabilityAppleMDMState means the inventory carries the macOS "mdm" block:
// enrollment state, ADE assignment and the provisioning UDID (#349).
const CapabilityAppleMDMState = "apple_mdm_state_v1"

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
	caps := append([]string{}, AgentCapabilities...)
	if pwshInstalled() {
		caps = append(caps, CapabilityScriptPwsh)
	}
	if goos == "darwin" {
		caps = append(caps, CapabilityAppleMDMState)
	}
	return caps
}
