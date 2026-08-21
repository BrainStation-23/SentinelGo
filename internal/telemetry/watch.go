package telemetry

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"sentinelgo/internal/models"
)

// A watch is one narrowly-scoped value that Phase G tracks across cycles.
//
// "Narrow" is a hard requirement, not a style preference. The change-detection
// layer persists every watched value on disk and puts before/after copies of it
// into events, so watching a whole section would mean keeping a second copy of
// the device's inventory locally and shipping fragments of it on every change.
// Every watch below resolves to a single scalar or a membership set of short
// identifiers, and WatchKeys/allowedValueFields exist so a test can prove no
// event can ever carry anything else.

// ValueKind describes how a watched value is compared.
type ValueKind string

const (
	// KindScalar is a single value — a boolean rendered as "true"/"false", an
	// enum like "enabled", or a short string such as a hostname. Compared for
	// equality.
	KindScalar ValueKind = "scalar"
	// KindMembership is a small set whose individual members matter, e.g. the
	// local administrators group. Each member is tracked as its own present/
	// absent watch, so "alice was added" is a distinct, separately-deduplicated
	// event from "bob was added".
	KindMembership ValueKind = "membership"
	// KindSetSummary is a set that is too large or too churny to track
	// per-member — installed patches, IP addresses. One event summarises the
	// cycle's additions and removals with a bounded sample.
	KindSetSummary ValueKind = "set_summary"
)

// Watch keys. These are part of the event contract: add, never rename. A
// renamed key looks like a brand-new value with no history, which re-seeds its
// baseline and silently swallows the first change after the rename.
const (
	WatchFirewallState        = "security_protection.firewall.state"
	WatchRealtimeProtection   = "security_protection.realtime_protection.state"
	WatchTamperProtection     = "security_protection.tamper_protection.state"
	WatchSecureBootState      = "secure_boot.state"
	WatchEncryptedVolumes     = "encryption.protected_volumes"
	WatchPrivilegedAccounts   = "security_posture.privileged_accounts"
	WatchHostname             = "identity.hostname"
	WatchIPv4Addresses        = "network.ipv4_addresses"
	WatchDomainJoined         = "directory.domain_joined"
	WatchEntraJoined          = "directory.entra_joined"
	WatchPendingReboot        = "os.pending_reboot"
	WatchInstalledPatches     = "patches.installed"
	membershipKeySeparator    = "#"
	maxSetSummarySampleLength = 10
)

// Transition maps a value change onto an event type.
//
// From and To are matched against the rendered value; the empty string matches
// anything. A transition with no matching rule produces NO event — that is the
// default, and it is why "enabled -> partial" on a firewall is silent while
// "enabled -> disabled" is critical.
type Transition struct {
	From      string
	To        string
	EventType string
}

// Watch is one tracked value.
type Watch struct {
	// Key identifies the watch. For KindMembership the per-member watch key is
	// Key + "#" + member.
	Key string
	// Section is the telemetry section the value is read from. A watch is only
	// evaluated when that section collected successfully this cycle.
	Section string
	Kind    ValueKind
	// Extract pulls the value out of the section's JSON document. Returning
	// false means "not trustworthy" and the watch is skipped entirely: the
	// stored value is left alone and no event can be produced. See
	// EventEngine.Process.
	Extract func(doc any) (Value, bool)
	// Transitions are consulted in order; the first match wins.
	Transitions []Transition
	// AddedEvent and RemovedEvent apply to set kinds.
	AddedEvent   string
	RemovedEvent string
}

// Value is a watched value in its comparable form.
type Value struct {
	Kind ValueKind `json:"kind"`
	// Scalar holds a scalar watch's rendered value.
	Scalar string `json:"scalar,omitempty"`
	// Members holds a set watch's members, sorted and deduplicated so the same
	// set always compares and hashes identically.
	Members []string `json:"members,omitempty"`
}

// ScalarValue builds a scalar value.
func ScalarValue(s string) Value { return Value{Kind: KindScalar, Scalar: s} }

// BoolValue renders a boolean as a scalar, so booleans and enums share one
// comparison and one transition-matching path.
func BoolValue(b bool) Value {
	if b {
		return ScalarValue("true")
	}
	return ScalarValue("false")
}

// SetValue builds a set value, normalising member order.
func SetValue(kind ValueKind, members []string) Value {
	seen := make(map[string]struct{}, len(members))
	out := make([]string, 0, len(members))
	for _, m := range members {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if _, dup := seen[m]; dup {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	sort.Strings(out)
	return Value{Kind: kind, Members: out}
}

// Equal reports whether two values are the same.
func (v Value) Equal(other Value) bool {
	if v.Kind != other.Kind || v.Scalar != other.Scalar || len(v.Members) != len(other.Members) {
		return false
	}
	for i := range v.Members {
		if v.Members[i] != other.Members[i] {
			return false
		}
	}
	return true
}

// Has reports whether a set value contains member.
func (v Value) Has(member string) bool {
	for _, m := range v.Members {
		if m == member {
			return true
		}
	}
	return false
}

// Encode renders the value for storage.
func (v Value) Encode() (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("telemetry: encode watched value: %w", err)
	}
	return string(b), nil
}

// DecodeValue parses a stored value.
func DecodeValue(s string) (Value, error) {
	var v Value
	if s == "" {
		return v, fmt.Errorf("telemetry: empty watched value")
	}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return Value{}, fmt.Errorf("telemetry: decode watched value: %w", err)
	}
	return v, nil
}

// MembershipKey returns the per-member watch key for a membership watch.
func MembershipKey(watchKey, member string) string {
	return watchKey + membershipKeySeparator + member
}

// SplitMembershipKey reverses MembershipKey.
func SplitMembershipKey(key string) (watchKey, member string, ok bool) {
	base, member, found := strings.Cut(key, membershipKeySeparator)
	if !found {
		return key, "", false
	}
	return base, member, true
}

// ---------------------------------------------------------------------------
// Extraction helpers.
//
// Watches read the section's JSON document rather than its Go type. The
// alternative — importing the collector packages here — is a cycle: every
// collector imports this package. Reading JSON also means a watch cannot
// accidentally reach a field the section does not actually put on the wire.
// ---------------------------------------------------------------------------

// unknownScalars are values that mean "the collector could not tell", and must
// never be stored or compared. Treating one as a real value is how a failed
// query becomes a false "firewall disabled" alert.
var unknownScalars = map[string]struct{}{
	"":            {},
	"unknown":     {},
	"unavailable": {},
	"not_present": {},
	"none":        {},
	"n/a":         {},
}

// TrustworthyScalar reports whether s is a real observation rather than a
// stand-in for "no answer".
func TrustworthyScalar(s string) bool {
	_, unknown := unknownScalars[strings.ToLower(strings.TrimSpace(s))]
	return !unknown
}

// lookup walks a JSON document by field path.
func lookup(doc any, path ...string) (any, bool) {
	cur := doc
	for _, field := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[field]
		if !ok || cur == nil {
			return nil, false
		}
	}
	return cur, true
}

// scalarAt extracts a string field, rejecting "unknown"-style placeholders.
func scalarAt(path ...string) func(any) (Value, bool) {
	return func(doc any) (Value, bool) {
		raw, ok := lookup(doc, path...)
		if !ok {
			return Value{}, false
		}
		s, ok := raw.(string)
		if !ok || !TrustworthyScalar(s) {
			return Value{}, false
		}
		return ScalarValue(s), true
	}
}

// boolAt extracts a boolean field. A field that is absent or null is untrusted
// rather than false: every optional boolean in these payloads is a pointer
// precisely so "we could not determine this" stays distinguishable from "no".
func boolAt(path ...string) func(any) (Value, bool) {
	return func(doc any) (Value, bool) {
		raw, ok := lookup(doc, path...)
		if !ok {
			return Value{}, false
		}
		b, ok := raw.(bool)
		if !ok {
			return Value{}, false
		}
		return BoolValue(b), true
	}
}

// listOf walks a JSON array at listPath and builds a set from each element,
// using pick to turn one element into zero or one member.
func listOf(kind ValueKind, listPath []string, pick func(item map[string]any) (string, bool)) func(any) (Value, bool) {
	return func(doc any) (Value, bool) {
		raw, ok := lookup(doc, listPath...)
		if !ok {
			// An absent list is untrusted, not empty. "The collector returned
			// no volumes" and "this device has no encrypted volumes" would
			// otherwise be the same input, and the second one is an alert.
			return Value{}, false
		}
		items, ok := raw.([]any)
		if !ok {
			return Value{}, false
		}

		members := make([]string, 0, len(items))
		for _, it := range items {
			m, ok := it.(map[string]any)
			if !ok {
				continue
			}
			if member, keep := pick(m); keep {
				members = append(members, member)
			}
		}
		return SetValue(kind, members), true
	}
}

// stringListAt builds a set from a flat JSON array of strings.
func stringListAt(kind ValueKind, path ...string) func(any) (Value, bool) {
	return func(doc any) (Value, bool) {
		raw, ok := lookup(doc, path...)
		if !ok {
			return Value{}, false
		}
		items, ok := raw.([]any)
		if !ok {
			return Value{}, false
		}
		members := make([]string, 0, len(items))
		for _, it := range items {
			if s, ok := it.(string); ok && TrustworthyScalar(s) {
				members = append(members, s)
			}
		}
		return SetValue(kind, members), true
	}
}

// DefaultWatches is the complete set of values Phase G tracks.
//
// Every entry is backed by a collector that this build actually ships and that
// reports a trustworthy value. Event types with no reliable source — USB
// insertion, service state, software install/remove — are deliberately absent
// rather than wired to a guess; see docs/telemetry for the blocked list.
func DefaultWatches() []Watch {
	return []Watch{
		{
			Key:     WatchFirewallState,
			Section: SectionProtection,
			Kind:    KindScalar,
			Extract: scalarAt("firewall", "state"),
			Transitions: []Transition{
				// Only a full "disabled" raises the alarm. A host that drops
				// one profile of three is degraded, not unprotected, and
				// treating "partial" as disabled would fire on every laptop
				// that joins a network with a different active profile.
				{To: "disabled", EventType: models.EventFirewallDisabled},
				{From: "disabled", To: "enabled", EventType: models.EventFirewallRestored},
				{From: "disabled", To: "partial", EventType: models.EventFirewallRestored},
			},
		},
		{
			Key:     WatchRealtimeProtection,
			Section: SectionProtection,
			Kind:    KindScalar,
			Extract: scalarAt("realtime_protection", "state"),
			Transitions: []Transition{
				{From: "enabled", To: "disabled", EventType: models.EventRealtimeProtectionDisabled},
				{From: "disabled", To: "enabled", EventType: models.EventRealtimeProtectionRestored},
			},
		},
		{
			Key:     WatchTamperProtection,
			Section: SectionProtection,
			Kind:    KindScalar,
			Extract: scalarAt("tamper_protection", "state"),
			Transitions: []Transition{
				{From: "enabled", To: "disabled", EventType: models.EventTamperProtectionDisabled},
				{From: "disabled", To: "enabled", EventType: models.EventTamperProtectionRestored},
			},
		},
		{
			Key:     WatchSecureBootState,
			Section: SectionSecureBoot,
			Kind:    KindScalar,
			Extract: scalarAt("state"),
			Transitions: []Transition{
				{From: "enabled", To: "disabled", EventType: models.EventSecureBootDisabled},
				{From: "disabled", To: "enabled", EventType: models.EventSecureBootRestored},
			},
		},
		{
			Key:     WatchEncryptedVolumes,
			Section: SectionEncryption,
			Kind:    KindMembership,
			// Membership is "which volumes have protection ON", so a volume
			// whose protection is turned off leaves the set and produces a
			// removal — the same signal as the volume disappearing entirely,
			// which is the correct reading either way.
			Extract: listOf(KindMembership, []string{"volumes"}, func(item map[string]any) (string, bool) {
				status, _ := item["protection_status"].(string)
				if !strings.EqualFold(status, "on") {
					return "", false
				}
				name, _ := item["mount_point"].(string)
				if name == "" {
					name, _ = item["drive_letter"].(string)
				}
				return name, name != ""
			}),
			RemovedEvent: models.EventEncryptionDisabled,
			AddedEvent:   models.EventEncryptionRestored,
		},
		{
			Key:          WatchPrivilegedAccounts,
			Section:      SectionSecurityPost,
			Kind:         KindMembership,
			Extract:      stringListAt(KindMembership, "privileged_accounts"),
			AddedEvent:   models.EventNewLocalAdmin,
			RemovedEvent: "", // Removal of an admin is not an exposure; no event.
		},
		{
			Key:         WatchHostname,
			Section:     SectionIdentity,
			Kind:        KindScalar,
			Extract:     scalarAt("hostname"),
			Transitions: []Transition{{EventType: models.EventHostnameChanged}},
		},
		{
			Key:     WatchIPv4Addresses,
			Section: SectionNetwork,
			Kind:    KindSetSummary,
			Extract: extractIPv4Addresses,
			// A summary set reports one event covering the cycle's additions
			// and removals, so both map to the same type.
			AddedEvent:   models.EventIPChanged,
			RemovedEvent: models.EventIPChanged,
		},
		{
			Key:         WatchDomainJoined,
			Section:     SectionDirectory,
			Kind:        KindScalar,
			Extract:     boolAt("domain_joined"),
			Transitions: []Transition{{EventType: models.EventDirectoryJoinChanged}},
		},
		{
			Key:         WatchEntraJoined,
			Section:     SectionDirectory,
			Kind:        KindScalar,
			Extract:     boolAt("entra_joined"),
			Transitions: []Transition{{EventType: models.EventEntraJoinChanged}},
		},
		{
			Key:     WatchPendingReboot,
			Section: SectionOS,
			Kind:    KindScalar,
			Extract: boolAt("pending_reboot"),
			Transitions: []Transition{
				// Only the rising edge is reported. A reboot clearing the flag
				// is the expected resolution, not news.
				{From: "false", To: "true", EventType: models.EventRebootRequired},
			},
		},
		{
			Key:     WatchInstalledPatches,
			Section: SectionPatches,
			Kind:    KindSetSummary,
			Extract: listOf(KindSetSummary, nil, func(item map[string]any) (string, bool) {
				status, _ := item["status"].(string)
				if !strings.EqualFold(status, "installed") {
					return "", false
				}
				id, _ := item["id"].(string)
				return id, id != ""
			}),
			AddedEvent: models.EventOSUpdateInstalled,
			// A patch leaving the installed set is usually a reporting quirk
			// (a superseded update disappearing from the list), not a real
			// uninstall, so it is not reported as one.
			RemovedEvent: "",
		},
	}
}

// extractIPv4Addresses flattens every interface's IPv4 list into one set.
//
// Loopback and link-local addresses are dropped: they are identical on every
// device and never change, so including them would only add noise to the stored
// baseline. A vanishing link-local address is not an IP change worth an event.
func extractIPv4Addresses(doc any) (Value, bool) {
	raw, ok := lookup(doc, "interfaces")
	if !ok {
		return Value{}, false
	}
	items, ok := raw.([]any)
	if !ok {
		return Value{}, false
	}

	var members []string
	for _, it := range items {
		iface, ok := it.(map[string]any)
		if !ok {
			continue
		}
		addrs, ok := iface["ipv4_addresses"].([]any)
		if !ok {
			continue
		}
		for _, a := range addrs {
			s, ok := a.(string)
			if !ok || !routableIPv4(s) {
				continue
			}
			members = append(members, s)
		}
	}
	return SetValue(KindSetSummary, members), true
}

// routableIPv4 filters out addresses that carry no information about where the
// device actually is.
func routableIPv4(s string) bool {
	switch {
	case s == "":
		return false
	case strings.HasPrefix(s, "127."):
		return false
	case strings.HasPrefix(s, "169.254."):
		return false
	default:
		return true
	}
}

// WatchKeys returns every watch key in sorted order.
func WatchKeys(watches []Watch) []string {
	keys := make([]string, 0, len(watches))
	for _, w := range watches {
		keys = append(keys, w.Key)
	}
	sort.Strings(keys)
	return keys
}
