// Package telemetry provides SentinelGo's additive enterprise-telemetry layer.
//
// The package sits alongside the existing inventory pipeline (internal/osinfo
// plus internal/service/agent) and deliberately does not modify it. It owns its
// own section registry, per-section change detection, local state, bounded
// outbound queue and wire envelope, so enterprise telemetry can grow without
// touching the legacy path or its fingerprint.
//
// The four logical classes below are kept distinct all the way to the wire so
// the backend can never mistake a health sample for an inventory snapshot.
package telemetry

// Class separates telemetry into the four kinds that must not be conflated.
type Class string

const (
	// ClassInventory is slow-changing state: identity, hardware, OS, software.
	ClassInventory Class = "inventory"
	// ClassPosture is security and compliance state, collected more often.
	ClassPosture Class = "posture"
	// ClassHealth is resource and device-health sampling. Health is never
	// fingerprinted or reconciled: a sample is a point in time, not a state.
	ClassHealth Class = "health"
	// ClassEvent is a discrete change that is reported when it happens.
	ClassEvent Class = "event"
)

// Valid reports whether c is a recognised class.
func (c Class) Valid() bool {
	switch c {
	case ClassInventory, ClassPosture, ClassHealth, ClassEvent:
		return true
	default:
		return false
	}
}

// Fingerprinted reports whether sections of this class take part in change
// detection. Health samples change on every read by definition, so hashing them
// would mark every cycle as changed and defeat reconciliation entirely.
func (c Class) Fingerprinted() bool {
	return c == ClassInventory || c == ClassPosture
}

func (c Class) String() string { return string(c) }
