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

// PriorityForEventType returns the delivery priority for an event type.
func PriorityForEventType(eventType string) EventPriority {
	if _, ok := criticalEventTypes[eventType]; ok {
		return PriorityCritical
	}
	return PriorityNormal
}

// IsCriticalEventType reports whether eventType uploads immediately.
func IsCriticalEventType(eventType string) bool {
	_, ok := criticalEventTypes[eventType]
	return ok
}
