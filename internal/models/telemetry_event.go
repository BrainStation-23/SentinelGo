package models

// TelemetryChangeEvent models a discrete change in endpoint state.
//
// It is deliberately a separate type from AuditLog. An audit log is an OS log
// record the agent forwarded; a telemetry change event is the agent's own
// assertion that a tracked property moved from one value to another. They have
// different producers, different schemas and different retention needs, so
// collapsing them into one table would make "when did BitLocker get turned off
// on this device" a text search over log messages instead of a query.
//
// The two may share transport (the durable queue) without sharing a model.
type TelemetryChangeEvent struct {
	EventID   string `json:"event_id"`
	EventType string `json:"event_type"`
	// Section is the telemetry section the change was detected in.
	Section  string        `json:"section"`
	Priority EventPriority `json:"priority"`
	Severity string        `json:"severity"`
	// OccurredAt is when the change happened, where the source can tell us.
	OccurredAt string `json:"occurred_at,omitempty"`
	// DetectedAt is when the agent noticed. For poll-based detection these
	// differ by up to one collection interval, and conflating them would
	// misdate every change.
	DetectedAt    string `json:"detected_at"`
	PreviousValue any    `json:"previous_value,omitempty"`
	CurrentValue  any    `json:"current_value,omitempty"`
	SchemaVersion int    `json:"schema_version"`
}

// EventPriority orders delivery. Lower values are more urgent.
type EventPriority int

const (
	// PriorityCritical bypasses the batch flush interval and uploads at once.
	// Reserved for controls whose loss leaves the endpoint exposed right now.
	PriorityCritical EventPriority = 0
	// PriorityHigh is sent on the next flush, ahead of normal traffic.
	PriorityHigh EventPriority = 10
	// PriorityNormal is ordinary batched inventory churn.
	PriorityNormal EventPriority = 50
	// PriorityLow is deferrable and evicted first under queue pressure.
	PriorityLow EventPriority = 80
)

// Immediate reports whether an event must bypass normal batching.
func (p EventPriority) Immediate() bool { return p <= PriorityCritical }

// TelemetryChangeEvent schema version.
const TelemetryChangeEventSchemaVersion = 1

// Critical event types: a protection was removed or a privilege was granted.
// These upload immediately.
const (
	EventFirewallDisabled           = "firewall_disabled"
	EventAntivirusDisabled          = "antivirus_disabled"
	EventRealtimeProtectionDisabled = "realtime_protection_disabled"
	EventEncryptionDisabled         = "encryption_disabled"
	EventNewLocalAdmin              = "new_local_admin"
	EventSecureBootDisabled         = "secure_boot_disabled"
	EventTamperProtectionDisabled   = "tamper_protection_disabled"
)

// Restore event types: a security control that was previously reported lost has
// come back.
//
// These exist so alert lifecycle stays entirely on the backend. Without a
// restore signal the backend can only close a firewall_disabled alert by
// timeout or by hand, which means either alerts that linger after the problem
// is fixed or alerts that close while the device is still exposed. The agent
// reports the transition; deciding what it does to an alert is the backend's
// job, not the endpoint's.
//
// They are High rather than Critical: a control coming back is good news, so it
// does not need to bypass batching, but it should still arrive ahead of routine
// inventory so an alert does not sit open longer than necessary.
const (
	EventFirewallRestored           = "firewall_restored"
	EventEncryptionRestored         = "encryption_restored"
	EventRealtimeProtectionRestored = "realtime_protection_restored"
	EventTamperProtectionRestored   = "tamper_protection_restored"
	EventSecureBootRestored         = "secure_boot_restored"
)

// High-priority event types: not an immediate exposure, but a change to the
// device's identity or trust relationships that an operator needs promptly.
const (
	EventDirectoryJoinChanged = "directory_join_changed"
	EventEntraJoinChanged     = "entra_join_changed"
	// EventPrivilegedAccountAdded covers a principal gaining privilege through
	// a source OTHER than the local administrative group, which is what
	// EventNewLocalAdmin already reports. No collector in this build supplies
	// such a source (it would need directory privileged-group membership), so
	// the type is defined for the backend contract but never emitted here. It
	// is listed as blocked rather than quietly mapped onto local admins, which
	// would double-report one change as two events.
	EventPrivilegedAccountAdded = "privileged_account_added"
)

// EventStateFlapping is the aggregate emitted when one watched value changes
// repeatedly inside the flapping window.
//
// It replaces the individual events for that value rather than accompanying
// them. A control that toggles every cycle — a firewall being restarted in a
// loop, a laptop roaming between networks — would otherwise generate an event
// storm, and a storm of critical events is worse than useless: it buries every
// other alert on the fleet. One event saying "this value is unstable" is both
// smaller and more actionable.
const EventStateFlapping = "watched_state_flapping"

// Normal event types: batched with ordinary telemetry.
const (
	EventSoftwareInstalled   = "software_installed"
	EventSoftwareRemoved     = "software_removed"
	EventServiceStateChanged = "service_state_changed"
	EventIPChanged           = "ip_changed"
	EventHostnameChanged     = "hostname_changed"
	EventUSBConnected        = "usb_connected"
	EventOSUpdateInstalled   = "os_update_installed"
	EventRebootRequired      = "reboot_required"
	EventPeripheralChanged   = "peripheral_changed"
)

// criticalEventTypes is the authoritative set of event types that bypass
// batching, so priority is decided in one place rather than at each call site.
var criticalEventTypes = map[string]struct{}{
	EventFirewallDisabled:           {},
	EventAntivirusDisabled:          {},
	EventRealtimeProtectionDisabled: {},
	EventEncryptionDisabled:         {},
	EventNewLocalAdmin:              {},
	EventSecureBootDisabled:         {},
	EventTamperProtectionDisabled:   {},
}

// highEventTypes upload ahead of routine telemetry without bypassing batching.
var highEventTypes = map[string]struct{}{
	EventFirewallRestored:           {},
	EventEncryptionRestored:         {},
	EventRealtimeProtectionRestored: {},
	EventTamperProtectionRestored:   {},
	EventSecureBootRestored:         {},
	EventDirectoryJoinChanged:       {},
	EventEntraJoinChanged:           {},
	EventPrivilegedAccountAdded:     {},
	EventStateFlapping:              {},
}

// Severity labels carried alongside priority. Priority orders delivery;
// severity is what the backend's alert rules read.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityNormal   = "normal"
)

// PriorityForEventType returns the delivery priority for an event type.
func PriorityForEventType(eventType string) EventPriority {
	if _, ok := criticalEventTypes[eventType]; ok {
		return PriorityCritical
	}
	if _, ok := highEventTypes[eventType]; ok {
		return PriorityHigh
	}
	return PriorityNormal
}

// SeverityForEventType returns the severity label for an event type.
func SeverityForEventType(eventType string) string {
	switch PriorityForEventType(eventType) {
	case PriorityCritical:
		return SeverityCritical
	case PriorityHigh:
		return SeverityHigh
	default:
		return SeverityNormal
	}
}

// IsHighEventType reports whether eventType is delivered ahead of routine
// telemetry.
func IsHighEventType(eventType string) bool {
	_, ok := highEventTypes[eventType]
	return ok
}

// IsCriticalEventType reports whether eventType uploads immediately.
func IsCriticalEventType(eventType string) bool {
	_, ok := criticalEventTypes[eventType]
	return ok
}
